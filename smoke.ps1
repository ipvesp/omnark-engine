param([string]$EnginePath, [switch]$ProbeDockerCli)

$ErrorActionPreference = 'Stop'

$engine = if ($EnginePath) { $EnginePath } else { Join-Path $PSScriptRoot 'bin\omnark-engine.exe' }
if (!(Test-Path -LiteralPath $engine)) { throw 'Build Omnark Engine first.' }
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$session = "NodecubEngineTest-$suffix"
$pipeName = "NodecubEngineTest-$suffix"
$storage = Join-Path ([IO.Path]::GetTempPath()) "omnark-engine-test-$suffix"
$storage = [IO.Path]::GetFullPath($storage)
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (!$storage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test storage path.' }
New-Item -ItemType Directory -Path $storage | Out-Null

function Invoke-Engine([hashtable]$request) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $pipeName, [IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect(10000)
        $pipe.ReadMode = [IO.Pipes.PipeTransmissionMode]::Message
        $bytes = [Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Compress -Depth 10))
        $pipe.Write($bytes, 0, $bytes.Length)
        $pipe.Flush()
        $buffer = New-Object byte[] 65536
        $stream = [IO.MemoryStream]::new()
        do {
            $count = $pipe.Read($buffer, 0, $buffer.Length)
            if ($count -eq 0) { throw 'Engine closed the pipe without a response.' }
            $stream.Write($buffer, 0, $count)
        } until ($pipe.IsMessageComplete)
        $response = [Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
        if (!$response.ok) { throw "Engine request $($request.op) failed: $($response.error)" }
        return $response
    } finally { $pipe.Dispose() }
}

function Invoke-EngineHttp([string]$method, [string]$path, [string]$body = '') {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', "OmnarkEngineApiTest-$suffix", [IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect(10000)
        $bodyBytes = [Text.Encoding]::UTF8.GetBytes($body)
        $request = "$method $path HTTP/1.1`r`nHost: omnark`r`nConnection: close`r`nContent-Length: $($bodyBytes.Length)`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($request)
        $pipe.Write($bytes, 0, $bytes.Length)
        if ($bodyBytes.Length) { $pipe.Write($bodyBytes, 0, $bodyBytes.Length) }
        $pipe.Flush()
        $reader = [IO.StreamReader]::new($pipe, [Text.Encoding]::UTF8, $false, 4096, $true)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $pipe.Dispose() }
}

$process = $null
$container = "omnark-smoke-$suffix"
try {
    $process = Start-Process -FilePath $engine -ArgumentList @($storage, '120000', $suffix) -PassThru -WindowStyle Hidden
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        Start-Sleep -Milliseconds 250
        try { $null = Invoke-Engine @{ op = 'ping' }; $ready = $true; break } catch { if ($process.HasExited) { throw "Engine exited: $($process.ExitCode)" } }
    }
    if (!$ready) { throw 'Test engine did not become ready.' }
    if ($ProbeDockerCli) {
        $docker = Get-Command docker.exe -ErrorAction Stop
        $hostAddress = "npipe:////./pipe/OmnarkEngineApiTest-$suffix"
        $versionOutput = & $docker.Source --host $hostAddress version --format '{{json .Server}}'
        if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '0\.1\.0-omnark') { throw 'Docker CLI version probe failed.' }
        $infoOutput = & $docker.Source --host $hostAddress info --format '{{.ServerVersion}} {{.Containers}}'
        if ($LASTEXITCODE -ne 0 -or $infoOutput -notmatch '^0\.1\.0-omnark\s+0$') { throw "Docker CLI empty engine info failed: $infoOutput" }
        $listOutput = & $docker.Source --host $hostAddress ps --all --format '{{json .}}'
        if ($LASTEXITCODE -ne 0) { throw 'Docker CLI empty container list failed.' }
    }
    if ((Invoke-EngineHttp 'GET' '/_ping') -notmatch '^HTTP/1\.1 200 OK') { throw 'API ping failed.' }
    $version = Invoke-EngineHttp 'GET' '/version'
    if ($version -notmatch '"ApiVersion":"1\.40"') { throw "API version failed: $version" }
    if ((Invoke-EngineHttp 'GET' '/not-implemented') -notmatch '^HTTP/1\.1 501 Not Implemented') { throw 'Unsupported API endpoint was not rejected.' }
    if ((Invoke-EngineHttp 'POST' '/v1.40/images/create?fromImage=docker.io/library/alpine&tag=3.24') -notmatch '^HTTP/1\.1 200 OK') { throw 'Engine API image pull failed.' }
    if ((Invoke-EngineHttp 'POST' '/v1.40/images/create?fromImage=--bad&tag=3.24') -notmatch '^HTTP/1\.1 400 Bad Request') { throw 'Unsafe pull reference was accepted.' }
    if ($ProbeDockerCli) {
        $pullOutput = & $docker.Source --host $hostAddress pull docker.io/library/alpine:3.24
        $pullExit = $LASTEXITCODE
        if ($pullExit -ne 0 -or (($pullOutput -join "`n") -notmatch 'Pull complete|up to date')) { throw 'Docker CLI pull failed.' }
        $imageOutput = & $docker.Source --host $hostAddress images --format '{{json .}}'
        if ($LASTEXITCODE -ne 0 -or $imageOutput -notmatch 'alpine') { throw 'Docker CLI image list failed.' }
    }
    $images = Invoke-Engine @{ op = 'images' }
    if (!$images.images -or !($images.images | Where-Object { $_.RepoTags -match 'alpine' })) { throw 'Engine SDK image listing failed.' }
    if ((Invoke-EngineHttp 'GET' '/v1.40/images/json') -notmatch 'alpine') { throw 'HTTP API image listing failed.' }
    $imageDetail = Invoke-EngineHttp 'GET' '/v1.40/images/docker.io/library/alpine:3.24/json'
    if ($imageDetail -notmatch '^HTTP/1\.1 200 OK' -or $imageDetail -notmatch 'alpine') { throw "HTTP API image inspection failed: $imageDetail" }
    if ($ProbeDockerCli) {
        $cliImage = & $docker.Source --host $hostAddress image inspect docker.io/library/alpine:3.24 --format '{{.Id}}'
        if ($LASTEXITCODE -ne 0 -or $cliImage -notmatch '^sha256:[a-f0-9]{64}$') { throw "Docker CLI image inspect failed: $cliImage" }
        $taggedImage = "omnark-smoke/alpine-$suffix`:test"
        & $docker.Source --host $hostAddress tag docker.io/library/alpine:3.24 $taggedImage
        if ($LASTEXITCODE -ne 0) { throw 'Docker CLI image tag failed.' }
        $taggedId = & $docker.Source --host $hostAddress image inspect $taggedImage --format '{{.Id}}'
        if ($LASTEXITCODE -ne 0 -or $taggedId -ne $cliImage) { throw 'Tagged image identity differs from source.' }
        if ((Invoke-EngineHttp 'DELETE' "/v1.40/images/$taggedImage`?force=true") -notmatch '^HTTP/1\.1 501 Not Implemented') { throw 'Unsupported forced image deletion was accepted.' }
        $removeImage = & $docker.Source --host $hostAddress image rm $taggedImage
        if ($LASTEXITCODE -ne 0 -or $removeImage -notmatch 'Untagged') { throw "Docker CLI image removal failed: $removeImage" }
        if ((Invoke-EngineHttp 'GET' "/v1.40/images/$taggedImage/json") -notmatch '^HTTP/1\.1 404 Not Found') { throw 'Removed image tag still exists.' }
        $sourceId = & $docker.Source --host $hostAddress image inspect docker.io/library/alpine:3.24 --format '{{.Id}}'
        if ($LASTEXITCODE -ne 0 -or $sourceId -ne $cliImage) { throw 'Removing a tag also removed the source image.' }
    }
    if ((Invoke-EngineHttp 'POST' '/v1.40/images/docker.io/library/alpine:3.24/tag?repo=../bad&tag=test') -notmatch '^HTTP/1\.1 400 Bad Request') { throw 'Unsafe image tag was accepted.' }
    if ((Invoke-EngineHttp 'GET' '/v1.40/images/../../json') -notmatch '^HTTP/1\.1 400 Bad Request') { throw 'Unsafe image reference was accepted.' }
    & (Join-Path $PSScriptRoot '..\..\scripts\smoke-image.ps1') -Session $session
    $createBody = @{ Image = 'docker.io/library/alpine:3.24'; Cmd = @('/bin/sh', '-c', 'sleep 60'); Hostname = 'omnark-smoke'; Domainname = 'example.test' } | ConvertTo-Json -Compress
    if ((Invoke-EngineHttp 'POST' '/v1.40/containers/create?name=..' $createBody) -notmatch '^HTTP/1\.1 400 Bad Request') { throw 'Unsafe container name was accepted.' }
    $invalidHostname = @{ Image = 'docker.io/library/alpine:3.24'; Cmd = @('sleep', '60'); Hostname = 'bad..host' } | ConvertTo-Json -Compress
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/create?name=$container" $invalidHostname) -notmatch '^HTTP/1\.1 400 Bad Request') { throw 'Unsafe hostname was accepted.' }
    $unsafeMount = @{ Image = 'docker.io/library/alpine:3.24'; Cmd = @('sleep', '60'); HostConfig = @{ Binds = @('safevol:/data/..') } } | ConvertTo-Json -Compress
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/create?name=$container" $unsafeMount) -notmatch '^HTTP/1\.1 400 Bad Request') { throw 'Unsafe mount target was accepted.' }
    $unsupported = Invoke-EngineHttp 'POST' "/v1.40/containers/create?name=$container" (@{ Image = 'docker.io/library/alpine:3.24'; Cmd = @('sleep', '60'); HostConfig = @{ SecurityOpt = @('no-new-privileges') } } | ConvertTo-Json -Compress)
    if ($unsupported -notmatch '^HTTP/1\.1 501 Not Implemented') { throw 'Unsupported create options were not rejected.' }
    $created = Invoke-EngineHttp 'POST' "/v1.40/containers/create?name=$container" $createBody
    if ($created -notmatch '^HTTP/1\.1 201 Created' -or $created -notmatch '"Id":') { throw "HTTP API create failed: $created" }
    if ($ProbeDockerCli) {
        $inspectOutput = & $docker.Source --host $hostAddress inspect $container --format '{{json .Id}}'
        if ($LASTEXITCODE -ne 0 -or $inspectOutput -notmatch '^["a-f0-9]{64,66}$') { throw 'Docker CLI inspect failed.' }
        $containerOutput = & $docker.Source --host $hostAddress ps --all --format '{{json .}}'
        if ($LASTEXITCODE -ne 0 -or $containerOutput -notmatch $container) { throw 'Docker CLI populated container list failed.' }
        $infoCount = & $docker.Source --host $hostAddress info --format '{{.Containers}}'
        if ($LASTEXITCODE -ne 0 -or [int]$infoCount -lt 1) { throw 'Docker CLI engine info omitted the created container.' }
    }
    $allList = ''
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $allList = Invoke-EngineHttp 'GET' '/v1.40/containers/json?all=1'
        if ($allList -match $container) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($allList -notmatch $container) { throw "API all-container list omitted the created container: $allList" }
    if ($allList -notmatch '^HTTP/1\.1 200 OK') { throw "API all-container list failed: $allList" }
    $listedContainer = ($allList.Split(@("`r`n`r`n"), 2, [StringSplitOptions]::None)[1] | ConvertFrom-Json) | Where-Object { $_.Names -contains "/$container" } | Select-Object -First 1
    if (!$listedContainer -or $listedContainer.Id.Length -ne 64 -or $listedContainer.State -ne 'created') { throw 'API container list has incomplete identity or state.' }
    if ((Invoke-EngineHttp 'GET' '/v1.40/containers/json') -match $container) { throw 'API running-container list included a stopped container.' }
    $detail = Invoke-EngineHttp 'GET' "/v1.40/containers/$container/json"
    if ($detail -notmatch '^HTTP/1\.1 200 OK') { throw 'API inspect failed.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/start") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API start failed.' }
    $hostnameOutput = & wslc.exe --session $session container exec $container hostname
    if ($LASTEXITCODE -ne 0 -or $hostnameOutput -ne 'omnark-smoke') { throw "Container hostname was not applied: $hostnameOutput" }
    $domainOutput = & wslc.exe --session $session container exec $container cat /proc/sys/kernel/domainname
    if ($LASTEXITCODE -ne 0 -or $domainOutput -ne 'example.test') { throw "Container domain name was not applied: $domainOutput" }
    $visible = $false
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if ((Invoke-EngineHttp 'GET' '/v1.40/containers/json') -match $container) { $visible = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (!$visible) { throw 'API running-container list omitted the started container.' }
    $top = ''
    for ($attempt = 0; $attempt -lt 8; $attempt++) {
        $top = Invoke-EngineHttp 'GET' "/v1.40/containers/$container/top"
        if ($top -match '^HTTP/1\.1 200 OK') { break }
        Start-Sleep -Milliseconds 250
    }
    if ($top -notmatch '^HTTP/1\.1 200 OK' -or $top -notmatch '"Processes"' -or $top -notmatch 'sleep') { throw "API top failed: $top" }
    $runningPrune = Invoke-EngineHttp 'POST' '/v1.40/containers/prune'
    if ($runningPrune -notmatch '^HTTP/1\.1 200 OK' -or $runningPrune -match [regex]::Escape($listedContainer.Id)) { throw 'Prune targeted a running container.' }
    $detail = Invoke-Engine @{ op = 'inspect'; name = $container }
    if ($detail.inspect.State.Running -ne $true) { throw 'Container did not start.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/restart") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API restart failed.' }
    $detail = Invoke-Engine @{ op = 'inspect'; name = $container }
    if ($detail.inspect.State.Running -ne $true) { throw 'Container did not restart.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/kill") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API kill failed.' }
    if ((Invoke-Engine @{ op = 'inspect'; name = $container }).inspect.State.Running -ne $false) { throw 'Container did not stop after kill.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/start") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API start after kill failed.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/stop") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API stop failed.' }
    $hidden = $false
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if ((Invoke-EngineHttp 'GET' '/v1.40/containers/json') -notmatch $container) { $hidden = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (!$hidden) { throw 'API running-container list retained the stopped container.' }
    $waited = Invoke-EngineHttp 'POST' "/v1.40/containers/$container/wait?condition=not-running"
    if ($waited -notmatch '^HTTP/1\.1 200 OK' -or $waited -notmatch '"StatusCode":') { throw "API wait for stopped container failed: $waited" }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/wait?condition=removed") -notmatch '^HTTP/1\.1 400 Bad Request') { throw 'Unsupported wait condition was accepted.' }
    if ((Invoke-EngineHttp 'DELETE' "/v1.40/containers/$container") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API remove failed.' }
    $exitContainer = "omnark-exit-$suffix"
    $exitBody = @{ Image = 'docker.io/library/alpine:3.24'; Cmd = @('/bin/sh', '-c', 'sleep 1; exit 7') } | ConvertTo-Json -Compress
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/create?name=$exitContainer" $exitBody) -notmatch '^HTTP/1\.1 201 Created') { throw 'API exit-code test container creation failed.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$exitContainer/start") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API exit-code test start failed.' }
    $exitWait = Invoke-EngineHttp 'POST' "/v1.40/containers/$exitContainer/wait"
    if ($exitWait -notmatch '^HTTP/1\.1 200 OK' -or $exitWait -notmatch '"StatusCode":7') { throw "API running-container wait failed: $exitWait" }
    if ((Invoke-EngineHttp 'DELETE' "/v1.40/containers/$exitContainer") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API exit-code test cleanup failed.' }
    $pruneCreated = Invoke-Engine @{ op = 'create'; name = $container; image = 'docker.io/library/alpine:3.24'; command = @('/bin/sh', '-c', 'sleep 60') }
    $pruned = Invoke-EngineHttp 'POST' '/v1.40/containers/prune?filters=%7B%7D'
    if ($pruned -notmatch '^HTTP/1\.1 200 OK' -or $pruned -notmatch [regex]::Escape($pruneCreated.id)) { throw 'Prune did not remove the stopped container.' }
    if ((Invoke-EngineHttp 'GET' "/v1.40/containers/$container/json") -notmatch '^HTTP/1\.1 404 Not Found') { throw 'Pruned container still exists.' }
    $volume = "omnark-vol-$suffix"
    $mapped = "omnark-mapped-$suffix"
    & wslc.exe --session $session volume create $volume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create test volume.' }
    $hostPort = (Get-Random -Minimum 40000 -Maximum 60000).ToString()
    $mappedBody = @{ Image = 'docker.io/library/alpine:3.24'; Cmd = @('/bin/sh', '-c', 'sleep 60'); ExposedPorts = @{ '8080/tcp' = @{} }; HostConfig = @{ NetworkMode = 'bridge'; Binds = @(('{0}:/data:ro' -f $volume)); PortBindings = @{ '8080/tcp' = @(@{ HostIp = '127.0.0.1'; HostPort = $hostPort }) } } } | ConvertTo-Json -Compress -Depth 8
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/create?name=$mapped" $mappedBody) -notmatch '^HTTP/1\.1 201 Created') { throw 'API create with volume and port binding failed.' }
    $mappedInspect = (Invoke-Engine @{ op = 'inspect'; name = $mapped }).inspect
    if ($mappedInspect.HostConfig.NetworkMode -ne 'bridge' -or $mappedInspect.Mounts.Count -ne 1 -or $mappedInspect.Mounts[0].Destination -ne '/data') { throw 'API create did not preserve network or volume options.' }
    if (($mappedInspect.Ports | ConvertTo-Json -Compress -Depth 8) -notmatch $hostPort) { throw 'API create did not preserve the host port binding.' }
    $mappedList = ''
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $mappedList = Invoke-EngineHttp 'GET' '/v1.40/containers/json?all=1'
        if ($mappedList -match $mapped) { break }
        Start-Sleep -Milliseconds 250
    }
    $mappedRow = ($mappedList.Split(@("`r`n`r`n"), 2, [StringSplitOptions]::None)[1] | ConvertFrom-Json) | Where-Object { $_.Names -contains "/$mapped" } | Select-Object -First 1
    if (!$mappedRow -or !$mappedRow.Ports -or $mappedRow.Ports[0].PublicPort -ne [int]$hostPort -or $mappedRow.Ports[0].PrivatePort -ne 8080) { throw 'API container list omitted the mapped port.' }
    $null = Invoke-Engine @{ op = 'remove'; name = $mapped }
    & wslc.exe --session $session volume rm $volume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove test volume.' }
    if ($ProbeDockerCli) {
        $cliContainer = "omnark-cli-$suffix"
        try {
            $cliCreate = & $docker.Source --host $hostAddress create --name $cliContainer docker.io/library/alpine:3.24 /bin/sh -c 'echo omnark-cli-log; sleep 60'
            if ($LASTEXITCODE -ne 0 -or $cliCreate -notmatch '^[a-f0-9]{64}$') { throw 'Docker CLI create failed.' }
            $cliStart = & $docker.Source --host $hostAddress start $cliContainer
            if ($LASTEXITCODE -ne 0 -or $cliStart -ne $cliContainer) { throw 'Docker CLI start failed.' }
            $cliTop = & $docker.Source --host $hostAddress top $cliContainer
            if ($LASTEXITCODE -ne 0 -or ($cliTop -join "`n") -notmatch 'sleep') { throw "Docker CLI top failed: $cliTop" }
            $cliLogs = ''
            for ($attempt = 0; $attempt -lt 20; $attempt++) {
                $cliLogs = & $docker.Source --host $hostAddress logs --tail 1 $cliContainer
                if ($LASTEXITCODE -ne 0) { throw 'Docker CLI logs failed.' }
                if ($cliLogs -match 'omnark-cli-log') { break }
                Start-Sleep -Milliseconds 250
            }
            if ($cliLogs -notmatch 'omnark-cli-log') { throw 'Docker CLI logs omitted container output.' }
            $future = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds().ToString()
            $timedLogs = & $docker.Source --host $hostAddress logs --timestamps --since 0 --until $future --tail 1 $cliContainer
            if ($LASTEXITCODE -ne 0 -or $timedLogs -notmatch 'omnark-cli-log' -or $timedLogs -notmatch '^\d{4}-\d{2}-\d{2}T') { throw 'Docker CLI filtered timestamps failed.' }
            $emptyLogs = & $docker.Source --host $hostAddress logs --tail 0 $cliContainer
            if ($LASTEXITCODE -ne 0 -or $emptyLogs) { throw 'Docker CLI zero-tail logs failed.' }
            if ((Invoke-EngineHttp 'GET' "/v1.40/containers/$cliContainer/logs?stdout=1&stderr=1&follow=1") -notmatch '^HTTP/1\.1 501 Not Implemented') { throw 'Unsupported live log following was not rejected.' }
            $cliStop = & $docker.Source --host $hostAddress stop $cliContainer
            if ($LASTEXITCODE -ne 0 -or $cliStop -ne $cliContainer) { throw 'Docker CLI stop failed.' }
            $cliWait = & $docker.Source --host $hostAddress wait $cliContainer
            if ($LASTEXITCODE -ne 0 -or $cliWait -notmatch '^\d+$') { throw "Docker CLI wait failed: $cliWait" }
            $cliRemove = & $docker.Source --host $hostAddress rm $cliContainer
            if ($LASTEXITCODE -ne 0 -or $cliRemove -ne $cliContainer) { throw 'Docker CLI remove failed.' }
            Write-Host 'Docker CLI version, info, pull, images, image inspect, image tag, image rm, ps, container inspect, create, start, logs, stop, wait, and rm passed.'
        } finally {
            try { $null = Invoke-Engine @{ op = 'remove'; name = $cliContainer } } catch { }
        }
    }
    & wslc.exe --session $session image prune --all --force | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Pruning images unused by all containers failed.' }
    $afterPrune = & wslc.exe --session $session image list --format json
    if ($LASTEXITCODE -ne 0 -or ($afterPrune -join "`n") -match 'alpine') { throw 'Unused Alpine image remained after prune.' }
    Write-Host 'Omnark Engine direct and HTTP API container operations passed.'
} finally {
    if ($process -and !$process.HasExited) {
        try {
            $event = [Threading.EventWaitHandle]::OpenExisting("Local\NodecubEngineTestStop-$suffix")
            try { $event.Set() | Out-Null } finally { $event.Dispose() }
            if (!$process.WaitForExit(15000)) { $process.Kill(); $process.WaitForExit(10000) | Out-Null }
        } catch {
            if (!$process.HasExited) { $process.Kill(); $process.WaitForExit(10000) | Out-Null }
        }
    }
    for ($attempt = 0; $attempt -lt 20 -and (Test-Path -LiteralPath $storage); $attempt++) {
        try { Remove-Item -LiteralPath $storage -Recurse -Force -ErrorAction Stop } catch { Start-Sleep -Milliseconds 500 }
    }
    if (Test-Path -LiteralPath $storage) { Write-Warning "Temporary test storage remains locked: $storage" }
}

