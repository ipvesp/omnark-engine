#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <sddl.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include "nlohmann/json.hpp"
#include "wslcsdk.h"

using json = nlohmann::json;

static bool safe_name(const std::string& value) {
    return !value.empty() && value.size() <= 128 && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
    });
}

static json create_container(WslcSession session, const json& request) {
    const std::string image = request.value("image", "");
    const std::string name = request.value("name", "");
    if (!safe_name(name) || image.empty() || image.size() > 255 || image.find_first_of(" \t\r\n") != std::string::npos || image.find('\0') != std::string::npos) {
        return {{"ok", false}, {"error", "Invalid image or container name"}};
    }
    const bool privileged = request.value("privileged", false);
    if (privileged) return {{"ok", false}, {"error", "Privileged containers are unavailable until cgroup support is verified"}};
    const auto commands = request.value("command", json::array());
    if (!commands.is_array() || commands.empty() || commands.size() > 64) {
        return {{"ok", false}, {"error", "A bounded command array is required"}};
    }
    std::vector<std::string> owned;
    std::vector<PCSTR> argv;
    for (const auto& part : commands) {
        if (!part.is_string()) return {{"ok", false}, {"error", "Command items must be strings"}};
        std::string value = part.get<std::string>();
        if (value.empty() || value.size() > 4096 || value.find('\0') != std::string::npos) {
            return {{"ok", false}, {"error", "Invalid command item"}};
        }
        owned.push_back(std::move(value));
    }
    for (const auto& part : owned) argv.push_back(part.c_str());
    WslcProcessSettings process_settings;
    HRESULT result = WslcInitProcessSettings(&process_settings);
    if (FAILED(result)) return {{"ok", false}, {"error", "Cannot initialize process settings"}};
    result = WslcSetProcessSettingsCmdLine(&process_settings, argv.data(), static_cast<uint32_t>(argv.size()));
    if (FAILED(result)) return {{"ok", false}, {"error", "Cannot set process command"}};
    const auto env = request.value("env", json::array());
    if (!env.is_array() || env.size() > 256) return {{"ok", false}, {"error", "Invalid environment list"}};
    std::vector<std::string> env_owned;
    std::vector<PCSTR> env_values;
    for (const auto& item : env) {
        if (!item.is_string()) return {{"ok", false}, {"error", "Invalid environment item"}};
        std::string value = item.get<std::string>();
        const auto equal = value.find('=');
        if (equal == std::string::npos || equal == 0 || value.size() > 16384 || value.find('\0') != std::string::npos) {
            return {{"ok", false}, {"error", "Invalid environment item"}};
        }
        env_owned.push_back(std::move(value));
    }
    for (const auto& value : env_owned) env_values.push_back(value.c_str());
    if (!env_values.empty() && FAILED(WslcSetProcessSettingsEnvVariables(&process_settings, env_values.data(), env_values.size()))) {
        return {{"ok", false}, {"error", "Cannot set environment"}};
    }
    const std::string workdir = request.value("workdir", "");
    if (!workdir.empty()) {
        if (workdir[0] != '/' || workdir.size() > 4096 || workdir.find('\0') != std::string::npos
            || FAILED(WslcSetProcessSettingsWorkingDirectory(&process_settings, workdir.c_str()))) {
            return {{"ok", false}, {"error", "Invalid working directory"}};
        }
    }
    WslcContainerSettings container_settings;
    result = WslcInitContainerSettings(image.c_str(), &container_settings);
    if (FAILED(result)) return {{"ok", false}, {"error", "Cannot initialize container settings"}};
    result = WslcSetContainerSettingsName(&container_settings, name.c_str());
    if (FAILED(result)) return {{"ok", false}, {"error", "Cannot set container name"}};
    result = WslcSetContainerSettingsInitProcess(&container_settings, &process_settings);
    if (FAILED(result)) return {{"ok", false}, {"error", "Cannot set init process"}};
    const auto volumes = request.value("volumes", json::array());
    if (!volumes.is_array() || volumes.size() > 32) return {{"ok", false}, {"error", "Invalid volume list"}};
    std::vector<std::pair<std::string, std::string>> volume_owned;
    std::vector<BOOL> volume_read_only;
    for (const auto& item : volumes) {
        if (!item.is_object()) return {{"ok", false}, {"error", "Invalid volume item"}};
        const std::string volume_name = item.value("name", "");
        const std::string volume_path = item.value("path", "");
        if (!safe_name(volume_name) || volume_path.empty() || volume_path[0] != '/' || volume_path.size() > 4096
            || volume_path.find('\0') != std::string::npos || volume_path.find("/../") != std::string::npos) {
            return {{"ok", false}, {"error", "Invalid volume item"}};
        }
        volume_owned.emplace_back(volume_name, volume_path);
        volume_read_only.push_back(item.value("readonly", false) ? TRUE : FALSE);
    }
    std::vector<WslcContainerNamedVolume> named_volumes;
    for (size_t index = 0; index < volume_owned.size(); ++index) {
        named_volumes.push_back({volume_owned[index].first.c_str(), volume_owned[index].second.c_str(), volume_read_only[index]});
    }
    if (!named_volumes.empty() && FAILED(WslcSetContainerSettingsNamedVolumes(&container_settings, named_volumes.data(), static_cast<uint32_t>(named_volumes.size())))) {
        return {{"ok", false}, {"error", "Cannot attach named volumes"}};
    }
    const auto ports = request.value("ports", json::array());
    if (!ports.is_array() || ports.size() > 32) return {{"ok", false}, {"error", "Invalid port list"}};
    std::vector<sockaddr_storage> addresses(ports.size());
    std::vector<WslcContainerPortMapping> mappings;
    for (size_t index = 0; index < ports.size(); ++index) {
        const auto& port = ports[index];
        if (!port.is_object()) return {{"ok", false}, {"error", "Invalid port item"}};
        const int host = port.value("host", 0);
        const int target = port.value("container", 0);
        const std::string protocol = port.value("protocol", "tcp");
        if (host < 1 || host > 65535 || target < 1 || target > 65535 || (protocol != "tcp" && protocol != "udp")) {
            return {{"ok", false}, {"error", "Invalid port item"}};
        }
        auto* address = reinterpret_cast<sockaddr_in*>(&addresses[index]);
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        mappings.push_back({static_cast<uint16_t>(host), static_cast<uint16_t>(target),
            protocol == "tcp" ? WSLC_PORT_PROTOCOL_TCP : WSLC_PORT_PROTOCOL_UDP, &addresses[index]});
    }
    if (!mappings.empty()) {
        if (FAILED(WslcSetContainerSettingsNetworkingMode(&container_settings, WSLC_CONTAINER_NETWORKING_MODE_BRIDGED))
            || FAILED(WslcSetContainerSettingsPortMappings(&container_settings, mappings.data(), static_cast<uint32_t>(mappings.size())))) {
            return {{"ok", false}, {"error", "Cannot set port mappings"}};
        }
    }
    WslcContainer container = nullptr;
    PWSTR error = nullptr;
    result = WslcCreateContainer(session, &container_settings, &container, &error);
    std::string message;
    if (error) { message = "WSL Container API rejected the request"; CoTaskMemFree(error); }
    if (FAILED(result)) return {{"ok", false}, {"error", message.empty() ? "Container creation failed" : message}, {"hresult", static_cast<uint32_t>(result)}};
    WslcReleaseContainer(container);
    return {{"ok", true}, {"name", name}};
}

static json manage_container(WslcSession session, const json& request, const std::string& op) {
    const std::string name = request.value("name", "");
    if (!safe_name(name)) return {{"ok", false}, {"error", "Invalid container name or ID"}};
    WslcContainer container = nullptr;
    PWSTR error = nullptr;
    const HRESULT opened = WslcOpenContainer(session, name.c_str(), &container, &error);
    if (error) CoTaskMemFree(error);
    if (FAILED(opened)) return {{"ok", false}, {"error", "Container not found"}, {"hresult", static_cast<uint32_t>(opened)}};
    json response = {{"ok", false}, {"error", "Container operation failed"}};
    if (op == "inspect") {
        PSTR detail = nullptr;
        const HRESULT result = WslcInspectContainer(container, &detail);
        if (SUCCEEDED(result) && detail) {
            json parsed = json::parse(detail, nullptr, false);
            if (!parsed.is_discarded()) response = {{"ok", true}, {"inspect", std::move(parsed)}};
        }
        if (detail) CoTaskMemFree(detail);
    } else {
        HRESULT result = E_INVALIDARG;
        if (op == "start") result = WslcStartContainer(container, WSLC_CONTAINER_START_FLAG_NONE, &error);
        else if (op == "stop") result = WslcStopContainer(container, WSLC_SIGNAL_SIGTERM, 10, &error);
        else if (op == "remove") result = WslcDeleteContainer(container, WSLC_DELETE_CONTAINER_FLAG_NONE, &error);
        if (error) CoTaskMemFree(error);
        if (SUCCEEDED(result)) response = {{"ok", true}, {"name", name}};
        else response["hresult"] = static_cast<uint32_t>(result);
    }
    WslcReleaseContainer(container);
    return response;
}

static bool user_only_security(SECURITY_ATTRIBUTES& attributes, PSECURITY_DESCRIPTOR& descriptor) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD length = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    std::vector<BYTE> data(length);
    const bool token_ok = GetTokenInformation(token, TokenUser, data.data(), length, &length) != 0;
    CloseHandle(token);
    if (!token_ok) return false;
    auto user = reinterpret_cast<TOKEN_USER*>(data.data());
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid)) return false;
    const std::wstring sddl = std::wstring(L"D:P(A;;GA;;;") + sid + L")";
    LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return false;
    attributes = {sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    return true;
}

static bool pipe_io(HANDLE pipe, bool write, char* buffer, DWORD size, DWORD& done, HANDLE stop, HANDLE terminated) {
    OVERLAPPED operation = {};
    operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!operation.hEvent) return false;
    const BOOL completed = write ? WriteFile(pipe, buffer, size, &done, &operation) : ReadFile(pipe, buffer, size, &done, &operation);
    bool ok = completed != 0;
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        HANDLE events[] = { stop, terminated, operation.hEvent };
        ok = WaitForMultipleObjects(3, events, FALSE, 10000) == WAIT_OBJECT_0 + 2
            && GetOverlappedResult(pipe, &operation, &done, FALSE) != 0;
    }
    if (!ok) CancelIoEx(pipe, &operation);
    CloseHandle(operation.hEvent);
    return ok;
}

static std::string http_reply(int status, const std::string& reason, const std::string& body, const std::string& content_type = "application/json") {
    return "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n"
        "Api-Version: 1.40\r\n\r\n" + body;
}

static std::string http_error(int status, const std::string& reason, const std::string& message) {
    return http_reply(status, reason, json({{"message", message}}).dump());
}

static std::string handle_http(WslcSession session, const std::string& request) {
    const auto line_end = request.find("\r\n");
    if (line_end == std::string::npos || line_end > 2048) return http_error(400, "Bad Request", "Invalid request line");
    const std::string line = request.substr(0, line_end);
    const auto first_space = line.find(' ');
    const auto last_space = line.rfind(' ');
    if (first_space == std::string::npos || last_space == first_space || line.substr(last_space + 1) != "HTTP/1.1")
        return http_error(400, "Bad Request", "Invalid HTTP request");
    const std::string method = line.substr(0, first_space);
    std::string path = line.substr(first_space + 1, last_space - first_space - 1);
    if (path.empty() || path[0] != '/' || path.find('?') != std::string::npos || path.find('#') != std::string::npos)
        return http_error(400, "Bad Request", "Invalid API path");
    if (path.rfind("/v1.", 0) == 0) {
        const auto slash = path.find('/', 2);
        if (slash == std::string::npos || path.substr(0, slash) != "/v1.40")
            return http_error(400, "Bad Request", "Unsupported API version");
        path.erase(0, slash);
    }
    if (path == "/_ping" && (method == "GET" || method == "HEAD"))
        return http_reply(200, "OK", method == "HEAD" ? "" : "OK", "text/plain");
    if (path == "/version" && method == "GET") {
        return http_reply(200, "OK", json({{"Version", "0.1.0-omnark"}, {"ApiVersion", "1.40"},
            {"MinAPIVersion", "1.40"}, {"GitCommit", ""}, {"GoVersion", ""},
            {"Os", "linux"}, {"Arch", "amd64"}, {"KernelVersion", ""},
            {"BuildTime", ""}, {"Experimental", false}}).dump());
    }
    constexpr const char* prefix = "/containers/";
    if (path.compare(0, std::strlen(prefix), prefix) == 0) {
        const auto name_start = std::strlen(prefix);
        const auto slash = path.find('/', name_start);
        const std::string name = path.substr(name_start, slash == std::string::npos ? std::string::npos : slash - name_start);
        const std::string suffix = slash == std::string::npos ? "" : path.substr(slash);
        if (!safe_name(name)) return http_error(400, "Bad Request", "Invalid container name or ID");
        std::string op;
        if (method == "GET" && suffix == "/json") op = "inspect";
        else if (method == "POST" && suffix == "/start") op = "start";
        else if (method == "POST" && suffix == "/stop") op = "stop";
        else if (method == "DELETE" && suffix.empty()) op = "remove";
        if (!op.empty()) {
            const json result = manage_container(session, {{"name", name}}, op);
            if (result.value("ok", false)) {
                if (op == "inspect") {
                    const std::string body = result.at("inspect").dump();
                    return body.size() <= 60000 ? http_reply(200, "OK", body)
                        : http_error(500, "Internal Server Error", "Container inspection exceeds response limit");
                }
                return http_reply(204, "No Content", "");
            }
            const std::string message = result.value("error", "Container operation failed");
            return message == "Container not found" ? http_error(404, "Not Found", message)
                : http_error(500, "Internal Server Error", message);
        }
    }
    return http_error(501, "Not Implemented", "This Engine API endpoint is not implemented by Omnark");
}

static int serve_http_pipe(WslcSession session, HANDLE stop, HANDLE terminated, const std::wstring& pipe_name) {
    SECURITY_ATTRIBUTES attributes = {};
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!user_only_security(attributes, descriptor)) return 1;
    int result = 0;
    while (true) {
        HANDLE pipe = CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 65536, 16384, 0, &attributes);
        if (pipe == INVALID_HANDLE_VALUE) { result = 1; break; }
        OVERLAPPED connection = {};
        connection.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!connection.hEvent) { CloseHandle(pipe); result = 1; break; }
        BOOL connected = ConnectNamedPipe(pipe, &connection);
        if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) SetEvent(connection.hEvent);
        else if (!connected && GetLastError() != ERROR_IO_PENDING) { CloseHandle(connection.hEvent); CloseHandle(pipe); result = 1; break; }
        else if (connected) SetEvent(connection.hEvent);
        HANDLE events[] = { stop, terminated, connection.hEvent };
        const DWORD wait = WaitForMultipleObjects(3, events, FALSE, INFINITE);
        if (wait != WAIT_OBJECT_0 + 2) {
            CancelIoEx(pipe, &connection);
            CloseHandle(connection.hEvent);
            CloseHandle(pipe);
            result = wait == WAIT_FAILED || wait == WAIT_OBJECT_0 + 1 ? 1 : 0;
            break;
        }
        CloseHandle(connection.hEvent);
        std::string request;
        char buffer[4096];
        DWORD received = 0;
        while (request.size() < 16384 && request.find("\r\n\r\n") == std::string::npos) {
            if (!pipe_io(pipe, false, buffer, sizeof(buffer), received, stop, terminated) || received == 0) break;
            request.append(buffer, received);
        }
        std::string response = request.find("\r\n\r\n") == std::string::npos
            ? http_error(400, "Bad Request", "HTTP headers are incomplete") : handle_http(session, request);
        DWORD sent = 0;
        pipe_io(pipe, true, response.data(), static_cast<DWORD>(response.size()), sent, stop, terminated);
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    LocalFree(descriptor);
    return result;
}

static int serve_pipe(WslcSession session, HANDLE stop, HANDLE terminated, DWORD timeout, const std::wstring& pipe_name) {
    SECURITY_ATTRIBUTES attributes = {};
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!user_only_security(attributes, descriptor)) return 1;
    const DWORD started = GetTickCount();
    int result = 0;
    while (true) {
        HANDLE pipe = CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 65536, 65536, 0, &attributes);
        if (pipe == INVALID_HANDLE_VALUE) { result = 1; break; }
        OVERLAPPED connection = {};
        connection.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!connection.hEvent) { CloseHandle(pipe); result = 1; break; }
        BOOL connected = ConnectNamedPipe(pipe, &connection);
        if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) SetEvent(connection.hEvent);
        else if (!connected && GetLastError() != ERROR_IO_PENDING) { CloseHandle(connection.hEvent); CloseHandle(pipe); result = 1; break; }
        else if (connected) SetEvent(connection.hEvent);
        HANDLE events[] = { stop, terminated, connection.hEvent };
        const DWORD remaining = timeout == INFINITE ? INFINITE : timeout - std::min(timeout, GetTickCount() - started);
        const DWORD wait = WaitForMultipleObjects(3, events, FALSE, remaining);
        if (wait != WAIT_OBJECT_0 + 2) {
            CancelIoEx(pipe, &connection);
            CloseHandle(connection.hEvent);
            CloseHandle(pipe);
            result = wait == WAIT_OBJECT_0 + 1 || wait == WAIT_FAILED ? 1 : 0;
            break;
        }
        CloseHandle(connection.hEvent);
        char buffer[65536];
        DWORD received = 0;
        json response = {{"ok", false}, {"error", "Invalid request"}};
        if (pipe_io(pipe, false, buffer, sizeof(buffer), received, stop, terminated)) {
            const auto request = json::parse(buffer, buffer + received, nullptr, false);
            if (request.is_object()) {
                try {
                    const std::string op = request.value("op", "");
                    if (op == "ping") response = {{"ok", true}, {"session", "NodecubEngine"}};
                    else if (op == "create") response = create_container(session, request);
                    else if (op == "inspect" || op == "start" || op == "stop" || op == "remove") response = manage_container(session, request, op);
                } catch (...) { response = {{"ok", false}, {"error", "Invalid container request"}}; }
            }
        }
        std::string output = response.dump();
        if (output.size() > 65536) output = json({{"ok", false}, {"error", "Engine response exceeds 64 KB"}}).dump();
        DWORD sent = 0;
        if (pipe_io(pipe, true, output.data(), static_cast<DWORD>(output.size()), sent, stop, terminated)) {
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    LocalFree(descriptor);
    return result;
}

int wmain(int argc, wchar_t** argv) {
    constexpr wchar_t stop_event_name[] = L"Local\\NodecubEngineStop-v1";
    if (argc == 2 && std::wcscmp(argv[1], L"--stop") == 0) {
        HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, stop_event_name);
        if (!event) return 1;
        const BOOL stopped = SetEvent(event);
        CloseHandle(event);
        return stopped ? 0 : 1;
    }
    if (argc < 2 || argc > 4) return 2;
    const DWORD timeout = argc >= 3 ? wcstoul(argv[2], nullptr, 10) : INFINITE;
    const bool test_instance = argc == 4;
    if (test_instance && (std::wcslen(argv[3]) == 0 || std::wcslen(argv[3]) > 32 ||
        !std::all_of(argv[3], argv[3] + std::wcslen(argv[3]), [](wchar_t ch) {
            return (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') || (ch >= L'0' && ch <= L'9') || ch == L'-';
        }))) return 2;
    const std::wstring session_name = test_instance ? std::wstring(L"NodecubEngineTest-") + argv[3] : L"NodecubEngine";
    const std::wstring pipe_name = test_instance ? std::wstring(L"\\\\.\\pipe\\NodecubEngineTest-") + argv[3] : L"\\\\.\\pipe\\NodecubEngine-v1";
    const std::wstring http_pipe_name = test_instance ? std::wstring(L"\\\\.\\pipe\\OmnarkEngineApiTest-") + argv[3] : L"\\\\.\\pipe\\omnark_engine";
    const std::wstring event_name = test_instance ? std::wstring(L"Local\\NodecubEngineTestStop-") + argv[3] : stop_event_name;
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized)) return 1;
    WslcSession session = nullptr;
    HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, event_name.c_str());
    if (!stop_event) { CoUninitialize(); return 1; }
    PWSTR error = nullptr;
    int result = 1;
    do {
        WslcComponentFlags missing = WSLC_COMPONENT_FLAG_NONE;
        if (FAILED(WslcGetMissingComponents(&missing)) || missing != WSLC_COMPONENT_FLAG_NONE) break;
        WslcSessionSettings settings;
        if (FAILED(WslcInitSessionSettings(session_name.c_str(), argv[1], &settings))) break;
        const HRESULT created = WslcCreateSession(&settings, &session, &error);
        if (FAILED(created)) {
            std::fprintf(stderr, "Session creation failed: 0x%08lx\n", static_cast<unsigned long>(created));
            if (error) std::fwprintf(stderr, L"%ls\n", error);
            break;
        }
        HANDLE terminated = nullptr;
        if (FAILED(WslcGetSessionTerminationEvent(session, &terminated))) break;
        std::printf("Nodecub engine ready\n");
        std::fflush(stdout);
        int http_result = 1;
        std::thread http_server([&] {
            const HRESULT thread_initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (SUCCEEDED(thread_initialized)) {
                http_result = serve_http_pipe(session, stop_event, terminated, http_pipe_name);
                CoUninitialize();
            }
        });
        result = serve_pipe(session, stop_event, terminated, timeout, pipe_name);
        SetEvent(stop_event);
        http_server.join();
        if (http_result != 0) result = 1;
    } while (false);
    if (error) CoTaskMemFree(error);
    if (session) WslcReleaseSession(session);
    CloseHandle(stop_event);
    CoUninitialize();
    return result;
}

