# Omnark Engine

Omnark Engine is a Windows container management process written in C++. It creates a dedicated WSL Containers SDK session and exposes a user-restricted local named pipe for container creation, inspection, start, stop, and removal. A separate HTTP named pipe implements an **incomplete** subset of the Docker Engine API. Unsupported endpoints return HTTP 501.

The engine does not implement Linux namespaces, cgroups, an OCI runtime, image storage, or registry protocols itself. Those capabilities are supplied by Microsoft's WSL Containers platform. It does not require Docker Desktop or the Docker CLI, but it requires a working WSL Containers installation. The `wslc.exe` command is used for container listing because the SDK does not expose a container enumeration function. The smoke test pulls its test image through the engine API.

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

The smoke test starts a separate temporary SDK session, tests both local pipes, pulls an Alpine test image through the engine API, and exercises image archive save/load, unused-image pruning, creation, listing, inspection, top, restart, kill, stop, wait, removal, stopped-container pruning, named volume mounts, and loopback port bindings. It closes the session and removes the temporary storage afterward. Pass `-EnginePath` to test another built engine binary. Optional `-ProbeDockerCli` checks version, info, pull, images, image inspect, image tag, image removal, ps, container inspect, create, start, top, logs, stop, wait, and rm with an installed Docker CLI pointed at the temporary Omnark pipe; Docker is only a test client and is not a runtime dependency.

## Local interfaces

- `\\.\pipe\NodecubEngine-v1`: bounded JSON message protocol retained for compatibility with the current Omnark desktop application.
- `\\.\pipe\omnark_engine`: HTTP/1.1 over a Windows named pipe, restricted to the current user and local clients. The implemented routes are `GET|HEAD /_ping`, `GET /version`, `GET /v1.40/info`, `GET /v1.40/images/json`, `GET /v1.40/images/{reference}/json`, `POST /v1.40/images/create?fromImage={reference}&tag={tag}`, `POST /v1.40/images/{reference}/tag?repo={repo}&tag={tag}`, `DELETE /v1.40/images/{reference}` (without force), `GET /v1.40/containers/json` (`?all=1` includes stopped containers), `POST /v1.40/containers/prune` (empty filters only), `POST /v1.40/containers/create?name={name}`, `GET /v1.40/containers/{id}/json`, `GET /v1.40/containers/{id}/top`, `GET /v1.40/containers/{id}/logs`, `POST /v1.40/containers/{id}/start`, `POST /v1.40/containers/{id}/stop`, `POST /v1.40/containers/{id}/restart`, `POST /v1.40/containers/{id}/kill`, `POST /v1.40/containers/{id}/wait` (default `not-running` condition only), and `DELETE /v1.40/containers/{id}`. Image pull uses the WSL Containers SDK and currently returns one completion event after the pull finishes. Creation accepts `Image`, `Cmd`, `Env`, `WorkingDir`, validated `Hostname` and `Domainname`, `ExposedPorts`, named-volume `HostConfig.Binds`, loopback `HostConfig.PortBindings`, and `HostConfig.NetworkMode` of `none`, `bridge`, or `default`. Unsupported nonempty options return HTTP 501. `/info` reports verified inventory counts and a limited system description. Container wait is limited to 60 seconds; the HTTP pipe has four concurrent instances so other requests can continue during a wait. Log retrieval supports bounded, non-following output up to 256 KB, including tail, timestamps, since, until, and details; separate stdout/stderr streams and live follow are not yet supported.

`GET /v1.40/containers/{id}/top` returns PID, user, and command for running containers. It uses `ps` inside the container image; images without `ps` receive HTTP 501. Custom `ps_args` are unsupported.

This repository contains only the engine source, build and smoke scripts, and third-party notices. It does not contain the Omnark desktop UI or Rust backend. The optional test verifies a limited Docker CLI lifecycle, but attach, live logs, full Compose, BuildKit, and IDE compatibility have **not** been established.

