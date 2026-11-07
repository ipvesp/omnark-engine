# Omnark Engine

Omnark Engine is a Windows container management process written in C++. It creates a dedicated WSL Containers SDK session and exposes a user-restricted local named pipe for container creation, inspection, start, stop, and removal. A separate HTTP named pipe implements an **incomplete** subset of the Docker Engine API. Unsupported endpoints return HTTP 501.

The engine does not implement Linux namespaces, cgroups, an OCI runtime, image storage, or registry protocols itself. Those capabilities are supplied by Microsoft's WSL Containers platform. It does not require Docker Desktop or the Docker CLI, but it requires a working WSL Containers installation. The `wslc.exe` command is used by the smoke test to pull its test image.

## Build

Requirements: Windows x64, WSL Containers, PowerShell, and Visual Studio C++ Build Tools.

```powershell
./build.ps1
```

The build script downloads Microsoft.WSL.Containers 3.0.3 and nlohmann/json 3.12.0, verifies their SHA-256 hashes, and creates `bin/omnark-engine.exe` beside `bin/wslcsdk.dll`. To build offline with already downloaded dependencies:

```powershell
./build.ps1 -SdkPackage C:\path\microsoft.wsl.containers.3.0.3.nupkg -JsonHeader C:\path\json.hpp
```

## Test

```powershell
./smoke.ps1
```

The smoke test starts a separate temporary SDK session, tests both local pipes, pulls an Alpine test image, creates a temporary container, and checks inspection, start, stop, and removal. It closes the session and removes the temporary storage afterward.

## Local interfaces

- `\\.\pipe\NodecubEngine-v1`: bounded JSON message protocol retained for compatibility with the current Omnark desktop application.
- `\\.\pipe\omnark_engine`: HTTP/1.1 over a Windows named pipe, restricted to the current user and local clients. The implemented routes are `GET|HEAD /_ping`, `GET /version`, `GET /v1.40/containers/{id}/json`, `POST /v1.40/containers/{id}/start`, `POST /v1.40/containers/{id}/stop`, and `DELETE /v1.40/containers/{id}`.

This repository contains only the engine source, build and smoke scripts, and third-party notices. It does not contain the Omnark desktop UI or Rust backend. Full Docker CLI, Compose, BuildKit, and IDE compatibility has **not** been established.

