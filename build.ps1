param(
    [string]$SdkPackage,
    [string]$JsonHeader
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$deps = Join-Path $root '.deps'
$build = Join-Path $root '.build'
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force $deps, $build, $bin | Out-Null

$sdkHash = '95A1E606BC15F363F85128B19A6BEFCDA0E4AAF770FC6B4BA2004EF275A03F1B'
$jsonHash = 'AAF127C04CB31C406E5B04A63F1AE89369FCCDE6D8FA7CDDA1ED4F32DFC5DE63'
$sdk = Join-Path $deps 'microsoft.wsl.containers.3.0.3.nupkg'
$header = Join-Path $deps 'include\nlohmann\json.hpp'

if ($SdkPackage) {
    Copy-Item -LiteralPath $SdkPackage -Destination $sdk -Force
} elseif (!(Test-Path -LiteralPath $sdk)) {
    Invoke-WebRequest -Uri 'https://api.nuget.org/v3-flatcontainer/microsoft.wsl.containers/3.0.3/microsoft.wsl.containers.3.0.3.nupkg' -OutFile $sdk
}
if ((Get-FileHash -LiteralPath $sdk -Algorithm SHA256).Hash -ne $sdkHash) { throw 'WSL Containers SDK checksum mismatch' }

New-Item -ItemType Directory -Force (Split-Path -Parent $header) | Out-Null
if ($JsonHeader) {
    Copy-Item -LiteralPath $JsonHeader -Destination $header -Force
} elseif (!(Test-Path -LiteralPath $header)) {
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/nlohmann/json/v3.12.0/single_include/nlohmann/json.hpp' -OutFile $header
}
if ((Get-FileHash -LiteralPath $header -Algorithm SHA256).Hash -ne $jsonHash) { throw 'nlohmann/json checksum mismatch' }

$sdkFiles = Join-Path $deps 'sdk'
if (!(Test-Path -LiteralPath (Join-Path $sdkFiles 'include\wslcsdk.h'))) {
    $zip = Join-Path $build 'sdk.zip'
    Copy-Item -LiteralPath $sdk -Destination $zip -Force
    Expand-Archive -LiteralPath $zip -DestinationPath $sdkFiles -Force
}
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio C++ Build Tools are required' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual Studio C++ Build Tools are required' }
$vsdev = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'
$source = Join-Path $root 'wslc_engine.cpp'
$output = Join-Path $bin 'omnark-engine.exe'
$object = Join-Path $build 'omnark-engine.obj'
$batch = Join-Path $build 'build.cmd'
$includes = Join-Path $deps 'include'
$sdkIncludes = Join-Path $sdkFiles 'include'
$library = Join-Path $sdkFiles 'runtimes\win-x64'
@"
@echo off
call "$vsdev" -arch=amd64 >nul
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++17 /I"$includes" /I"$sdkIncludes" /Fo:"$object" "$source" /Fe:"$output" /link /LIBPATH:"$library" /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup wslcsdk.lib ole32.lib advapi32.lib ws2_32.lib
exit /b %errorlevel%
"@ | Set-Content -LiteralPath $batch -Encoding ascii
& cmd.exe /c $batch
if ($LASTEXITCODE -ne 0) { throw 'Omnark Engine compilation failed' }
Copy-Item -LiteralPath (Join-Path $library 'native\wslcsdk.dll') -Destination (Join-Path $bin 'wslcsdk.dll') -Force
Write-Host "Built $output"

