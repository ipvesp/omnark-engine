$ErrorActionPreference = 'Stop'

$engine = Join-Path $PSScriptRoot 'bin\omnark-engine.exe'
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

function Invoke-EngineHttp([string]$method, [string]$path) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', "OmnarkEngineApiTest-$suffix", [IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect(10000)
        $request = "$method $path HTTP/1.1`r`nHost: omnark`r`nConnection: close`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($request)
        $pipe.Write($bytes, 0, $bytes.Length)
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
    if ((Invoke-EngineHttp 'GET' '/_ping') -notmatch '^HTTP/1\.1 200 OK') { throw 'API ping failed.' }
    $version = Invoke-EngineHttp 'GET' '/version'
    if ($version -notmatch '"ApiVersion":"1\.40"') { throw "API version failed: $version" }
    if ((Invoke-EngineHttp 'GET' '/not-implemented') -notmatch '^HTTP/1\.1 501 Not Implemented') { throw 'Unsupported API endpoint was not rejected.' }
    & wslc.exe --session $session pull docker.io/library/alpine:3.24 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not pull the test image.' }
    $null = Invoke-Engine @{ op = 'create'; name = $container; image = 'docker.io/library/alpine:3.24'; command = @('/bin/sh', '-c', 'sleep 60') }
    $detail = Invoke-EngineHttp 'GET' "/v1.40/containers/$container/json"
    if ($detail -notmatch '^HTTP/1\.1 200 OK') { throw 'API inspect failed.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/start") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API start failed.' }
    $detail = Invoke-Engine @{ op = 'inspect'; name = $container }
    if ($detail.inspect.State.Running -ne $true) { throw 'Container did not start.' }
    if ((Invoke-EngineHttp 'POST' "/v1.40/containers/$container/stop") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API stop failed.' }
    if ((Invoke-EngineHttp 'DELETE' "/v1.40/containers/$container") -notmatch '^HTTP/1\.1 204 No Content') { throw 'API remove failed.' }
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

