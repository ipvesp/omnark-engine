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
#include <cctype>
#include <ctime>
#include <thread>
#include <sstream>
#include "nlohmann/json.hpp"
#include "wslcsdk.h"

using json = nlohmann::json;

static bool safe_name(const std::string& value) {
    return !value.empty() && value.size() <= 128
        && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= '0' && value[0] <= '9'))
        && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
    });
}

static bool safe_image_reference(const std::string& value) {
    return !value.empty() && value.size() <= 255 && value[0] != '-' && value[0] != '.'
        && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
                || ch == '_' || ch == '-' || ch == '.' || ch == '/' || ch == ':' || ch == '@';
        }) && value.find("..") == std::string::npos && value.find("//") == std::string::npos;
}

static bool safe_dns_name(const std::string& value) {
    if (value.empty() || value.size() > 253 || value.back() == '.') return false;
    size_t cursor = 0;
    while (cursor < value.size()) {
        const size_t end = value.find('.', cursor);
        const size_t length = (end == std::string::npos ? value.size() : end) - cursor;
        if (length == 0 || length > 63 || value[cursor] == '-' || value[cursor + length - 1] == '-') return false;
        for (size_t index = cursor; index < cursor + length; ++index) {
            const unsigned char ch = static_cast<unsigned char>(value[index]);
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-')) return false;
        }
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    return true;
}

static bool safe_container_path(const std::string& value) {
    if (value.empty() || value[0] != '/' || value.size() > 4096 || value.find('\0') != std::string::npos) return false;
    size_t cursor = 1;
    while (cursor < value.size()) {
        const size_t end = value.find('/', cursor);
        const std::string part = value.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
        if (part == "." || part == "..") return false;
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    return true;
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
        if (!safe_container_path(workdir)
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
    const std::string hostname = request.value("hostname", "");
    const std::string domainname = request.value("domainname", "");
    if ((!hostname.empty() && (!safe_dns_name(hostname) || hostname.find('.') != std::string::npos))
        || (!domainname.empty() && !safe_dns_name(domainname)))
        return {{"ok", false}, {"error", "Invalid hostname or domain name"}};
    if (!hostname.empty() && FAILED(WslcSetContainerSettingsHostName(&container_settings, hostname.c_str())))
        return {{"ok", false}, {"error", "Cannot set hostname"}};
    if (!domainname.empty() && FAILED(WslcSetContainerSettingsDomainName(&container_settings, domainname.c_str())))
        return {{"ok", false}, {"error", "Cannot set domain name"}};
    const auto volumes = request.value("volumes", json::array());
    if (!volumes.is_array() || volumes.size() > 32) return {{"ok", false}, {"error", "Invalid volume list"}};
    std::vector<std::pair<std::string, std::string>> volume_owned;
    std::vector<BOOL> volume_read_only;
    for (const auto& item : volumes) {
        if (!item.is_object()) return {{"ok", false}, {"error", "Invalid volume item"}};
        const std::string volume_name = item.value("name", "");
        const std::string volume_path = item.value("path", "");
        if (!safe_name(volume_name) || !safe_container_path(volume_path)) {
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
    const std::string network = request.value("network", "");
    if (network != "" && network != "bridge" && network != "none") return {{"ok", false}, {"error", "Unsupported network mode"}};
    if (network == "none" && !mappings.empty()) return {{"ok", false}, {"error", "Port mappings require bridged networking"}};
    if (network == "bridge" || !mappings.empty()) {
        if (FAILED(WslcSetContainerSettingsNetworkingMode(&container_settings, WSLC_CONTAINER_NETWORKING_MODE_BRIDGED))) {
            return {{"ok", false}, {"error", "Cannot enable bridged networking"}};
        }
    }
    if (!mappings.empty()) {
        if (FAILED(WslcSetContainerSettingsPortMappings(&container_settings, mappings.data(), static_cast<uint32_t>(mappings.size())))) {
            return {{"ok", false}, {"error", "Cannot set port mappings"}};
        }
    }
    WslcContainer container = nullptr;
    PWSTR error = nullptr;
    result = WslcCreateContainer(session, &container_settings, &container, &error);
    std::string message;
    if (error) { message = "WSL Container API rejected the request"; CoTaskMemFree(error); }
    if (FAILED(result)) return {{"ok", false}, {"error", message.empty() ? "Container creation failed" : message}, {"hresult", static_cast<uint32_t>(result)}};
    CHAR id[WSLC_CONTAINER_ID_BUFFER_SIZE] = {};
    const HRESULT id_result = WslcGetContainerID(container, id);
    WslcReleaseContainer(container);
    return {{"ok", true}, {"name", name}, {"id", SUCCEEDED(id_result) ? std::string(id) : name}};
}

static json manage_container(WslcSession session, const json& request, const std::string& op) {
    const std::string name = request.value("name", "");
    if (!safe_name(name)) return {{"ok", false}, {"error", "Invalid container name or ID"}};
    WslcContainer container = nullptr;
    PWSTR error = nullptr;
    const HRESULT opened = WslcOpenContainer(session, name.c_str(), &container, &error);
    if (error) { CoTaskMemFree(error); error = nullptr; }
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
        else if (op == "kill") result = WslcStopContainer(container, WSLC_SIGNAL_SIGKILL, 0, &error);
        else if (op == "restart") {
            result = WslcStopContainer(container, WSLC_SIGNAL_SIGTERM, 10, &error);
            if (error) { CoTaskMemFree(error); error = nullptr; }
            if (SUCCEEDED(result)) result = WslcStartContainer(container, WSLC_CONTAINER_START_FLAG_NONE, &error);
        }
        else if (op == "remove") result = WslcDeleteContainer(container, WSLC_DELETE_CONTAINER_FLAG_NONE, &error);
        if (error) CoTaskMemFree(error);
        if (SUCCEEDED(result)) response = {{"ok", true}, {"name", name}};
        else response["hresult"] = static_cast<uint32_t>(result);
    }
    WslcReleaseContainer(container);
    return response;
}

static json list_session_images(WslcSession session) {
    WslcImageInfo* images = nullptr;
    uint32_t count = 0;
    const HRESULT result = WslcListSessionImages(session, &images, &count);
    if (FAILED(result)) return {{"ok", false}, {"error", "Cannot list session images"}, {"hresult", static_cast<uint32_t>(result)}};
    json rows = json::array();
    constexpr char hex[] = "0123456789abcdef";
    for (uint32_t index = 0; index < count; ++index) {
        const auto& image = images[index];
        const size_t length = strnlen_s(image.name, sizeof(image.name));
        const std::string name(image.name, length);
        std::string digest = "sha256:";
        digest.reserve(71);
        for (const auto byte : image.sha256) {
            digest.push_back(hex[byte >> 4]);
            digest.push_back(hex[byte & 15]);
        }
        rows.push_back({{"Id", digest}, {"RepoTags", json::array({name})}, {"RepoDigests", json::array()},
            {"Created", image.createdUnixTime}, {"Size", image.sizeBytes},
            {"SharedSize", -1}, {"VirtualSize", image.sizeBytes}, {"Containers", 0},
            {"Labels", json::object()}});
    }
    if (images) CoTaskMemFree(images);
    return {{"ok", true}, {"images", std::move(rows)}};
}

static bool run_wslc_command(const std::wstring& session_name, const std::wstring& arguments,
    std::string& output, size_t max_bytes = 1024 * 1024, DWORD timeout_ms = 15000) {
    const DWORD path_length = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    if (!path_length || path_length > 32768) return false;
    std::wstring search_path(path_length, L'\0');
    if (!GetEnvironmentVariableW(L"PATH", search_path.data(), path_length)) return false;
    search_path.resize(path_length - 1);
    const DWORD executable_length = SearchPathW(search_path.c_str(), L"wslc.exe", nullptr, 0, nullptr, nullptr);
    if (!executable_length || executable_length > 32768) return false;
    std::wstring executable(executable_length, L'\0');
    if (!SearchPathW(search_path.c_str(), L"wslc.exe", nullptr, executable_length, executable.data(), nullptr)) return false;
    executable.resize(executable_length - 1);

    SECURITY_ATTRIBUTES attributes = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_pipe = nullptr, write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &attributes, 0)) return false;
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
    HANDLE null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (null_input == INVALID_HANDLE_VALUE) { CloseHandle(read_pipe); CloseHandle(write_pipe); return false; }
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = null_input;
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    PROCESS_INFORMATION process = {};
    std::wstring command = L"\"" + executable + L"\" --session " + session_name + L" " + arguments;
    const BOOL started = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(write_pipe);
    CloseHandle(null_input);
    if (!started) { CloseHandle(read_pipe); return false; }
    bool ok = true;
    const DWORD start = GetTickCount();
    char buffer[4096];
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr)) {
            if (GetLastError() == ERROR_BROKEN_PIPE && WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) break;
            ok = false;
            break;
        }
        if (available) {
            DWORD received = 0;
            if (!ReadFile(read_pipe, buffer, std::min<DWORD>(available, sizeof(buffer)), &received, nullptr)) { ok = false; break; }
            if (output.size() + received > max_bytes) { ok = false; break; }
            output.append(buffer, received);
        } else if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) {
            break;
        } else if (GetTickCount() - start > timeout_ms) {
            ok = false;
            break;
        } else {
            Sleep(10);
        }
    }
    if (!ok) TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, 5000);
    DWORD exit_code = 1;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(read_pipe);
    return ok && exit_code == 0;
}

static int64_t container_created(const std::string& value) {
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, offset_hour = 0, offset_minute = 0;
    char sign = '+';
    if (std::sscanf(value.c_str(), "%d-%d-%d %d:%d:%d %c%2d%2d", &year, &month, &day,
        &hour, &minute, &second, &sign, &offset_hour, &offset_minute) != 9) return 0;
    if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59
        || second > 60 || offset_hour > 23 || offset_minute > 59 || (sign != '+' && sign != '-')) return 0;
    std::tm utc = {};
    utc.tm_year = year - 1900;
    utc.tm_mon = month - 1;
    utc.tm_mday = day;
    utc.tm_hour = hour;
    utc.tm_min = minute;
    utc.tm_sec = second;
    const int64_t timestamp = _mkgmtime64(&utc);
    return timestamp - (sign == '+' ? 1 : -1) * (offset_hour * 3600 + offset_minute * 60);
}

static json docker_ports(const json& inspected);

static json list_session_containers(WslcSession session, const std::wstring& session_name, bool all) {
    std::string output;
    bool listed = false;
    for (int attempt = 0; attempt < 8; ++attempt) {
        output.clear();
        if (run_wslc_command(session_name, L"container list --all --format json", output)) { listed = true; break; }
        if (attempt < 7) Sleep(250);
    }
    if (!listed) return {{"ok", false}, {"error", "Cannot list session containers"}};
    json rows = json::array();
    size_t cursor = 0;
    while (cursor < output.size()) {
        const size_t end = output.find('\n', cursor);
        const std::string line = output.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
        cursor = end == std::string::npos ? output.size() : end + 1;
        if (line.find_first_not_of(" \r\t") == std::string::npos) continue;
        const json row = json::parse(line, nullptr, false);
        if (!row.is_object()) return {{"ok", false}, {"error", "Invalid container list response"}};
        const std::string name = row.value("Names", "");
        if (!safe_name(name)) return {{"ok", false}, {"error", "Invalid listed container name"}};
        std::string id = row.value("ID", "");
        json inspected = json::object();
        WslcContainer container = nullptr;
        PWSTR error = nullptr;
        if (SUCCEEDED(WslcOpenContainer(session, name.c_str(), &container, &error))) {
            CHAR full_id[WSLC_CONTAINER_ID_BUFFER_SIZE] = {};
            if (SUCCEEDED(WslcGetContainerID(container, full_id))) id = full_id;
            PSTR detail = nullptr;
            if (SUCCEEDED(WslcInspectContainer(container, &detail)) && detail) {
                inspected = json::parse(detail, nullptr, false);
                if (!inspected.is_object()) inspected = json::object();
            }
            if (detail) CoTaskMemFree(detail);
            WslcReleaseContainer(container);
        }
        if (error) CoTaskMemFree(error);
        const json state = inspected.value("State", json::object());
        const std::string status = state.is_object() ? state.value("Status", row.value("State", "")) : row.value("State", "");
        if (!all && status != "running") continue;
        rows.push_back({{"Id", id}, {"Names", json::array({"/" + name})}, {"Image", row.value("Image", "")},
            {"ImageID", inspected.value("Image", "")}, {"Command", row.value("Command", "")},
            {"Created", container_created(row.value("CreatedAt", ""))}, {"Ports", docker_ports(inspected)},
            {"Labels", inspected.value("Labels", json::object())}, {"State", status}, {"Status", row.value("Status", "")},
            {"HostConfig", inspected.value("HostConfig", json::object())},
            {"NetworkSettings", inspected.value("NetworkSettings", json::object())},
            {"Mounts", inspected.value("Mounts", json::array())}});
    }
    return {{"ok", true}, {"containers", std::move(rows)}};
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

static bool http_body_length(const std::string& request, size_t header_end, size_t& length) {
    length = 0;
    bool seen = false;
    size_t cursor = request.find("\r\n") + 2;
    while (cursor < header_end) {
        const size_t end = request.find("\r\n", cursor);
        if (end == std::string::npos || end > header_end) return false;
        const size_t colon = request.find(':', cursor);
        if (colon == std::string::npos || colon >= end) return false;
        std::string key = request.substr(cursor, colon - cursor);
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (key == "transfer-encoding") return false;
        if (key == "content-length") {
            if (seen) return false;
            seen = true;
            size_t first = colon + 1;
            while (first < end && request[first] == ' ') ++first;
            if (first == end) return false;
            size_t parsed = 0;
            for (size_t index = first; index < end; ++index) {
                const char digit = request[index];
                if (digit < '0' || digit > '9' || parsed > (16384 - (digit - '0')) / 10) return false;
                parsed = parsed * 10 + digit - '0';
            }
            length = parsed;
        }
        cursor = end + 2;
    }
    return true;
}

static bool empty_json_value(const json& value) {
    return value.is_null() || (value.is_boolean() && !value.get<bool>())
        || (value.is_number() && value == 0)
        || (value.is_string() && value.get<std::string>().empty())
        || (value.is_array() && value.empty()) || (value.is_object() && value.empty());
}

static int decimal_port(const std::string& value) {
    if (value.empty() || value.size() > 5) return 0;
    int port = 0;
    for (const char digit : value) {
        if (digit < '0' || digit > '9') return 0;
        port = port * 10 + digit - '0';
    }
    return port > 0 && port <= 65535 ? port : 0;
}

static bool container_port_key(const std::string& value, int& port, std::string& protocol) {
    const size_t slash = value.find('/');
    if (slash == std::string::npos) return false;
    port = decimal_port(value.substr(0, slash));
    protocol = value.substr(slash + 1);
    return port != 0 && (protocol == "tcp" || protocol == "udp");
}

static json docker_ports(const json& inspected) {
    json result = json::array();
    if (!inspected.contains("Ports") || !inspected["Ports"].is_object()) return result;
    for (auto it = inspected["Ports"].begin(); it != inspected["Ports"].end(); ++it) {
        int private_port = 0;
        std::string protocol;
        if (!container_port_key(it.key(), private_port, protocol)) continue;
        const json& bindings = it.value();
        if (bindings.is_null() || (bindings.is_array() && bindings.empty())) {
            result.push_back({{"PrivatePort", private_port}, {"Type", protocol}});
            continue;
        }
        const json entries = bindings.is_array() ? bindings : json::array({bindings});
        for (const auto& binding : entries) {
            if (!binding.is_object()) continue;
            const std::string public_text = binding.value("HostPort", "");
            const int public_port = decimal_port(public_text);
            if (public_port) result.push_back({{"IP", binding.value("HostIp", "")},
                {"PrivatePort", private_port}, {"PublicPort", public_port}, {"Type", protocol}});
        }
    }
    return result;
}

static int hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool log_time_value(const std::string& encoded, std::string& decoded) {
    if (encoded.empty() || encoded.size() > 96) return false;
    decoded.clear();
    for (size_t index = 0; index < encoded.size(); ++index) {
        char ch = encoded[index];
        if (ch == '%') {
            if (index + 2 >= encoded.size()) return false;
            const int high = hex_digit(encoded[index + 1]);
            const int low = hex_digit(encoded[index + 2]);
            if (high < 0 || low < 0) return false;
            ch = static_cast<char>(high * 16 + low);
            index += 2;
        }
        if (!((ch >= '0' && ch <= '9') || ch == '-' || ch == ':' || ch == '+' || ch == '.' || ch == 'T' || ch == 'Z'))
            return false;
        decoded.push_back(ch);
    }
    return !decoded.empty() && decoded.size() <= 64 && decoded[0] >= '0' && decoded[0] <= '9';
}

static std::string http_create_container(WslcSession session, const std::string& name, const std::string& body) {
    if (!safe_name(name)) return http_error(400, "Bad Request", "A valid container name is required");
    const json input = json::parse(body, nullptr, false);
    if (!input.is_object()) return http_error(400, "Bad Request", "Invalid container JSON");
    std::string unsupported;
    for (auto it = input.begin(); it != input.end(); ++it) {
        if (it.key() != "Image" && it.key() != "Cmd" && it.key() != "Env" && it.key() != "WorkingDir"
            && it.key() != "Hostname" && it.key() != "Domainname"
            && it.key() != "ExposedPorts" && it.key() != "AttachStdout" && it.key() != "AttachStderr"
            && it.key() != "NetworkingConfig"
            && it.key() != "HostConfig" && !empty_json_value(it.value()))
            unsupported += (unsupported.empty() ? "" : ", ") + it.key();
    }
    if (!unsupported.empty()) return http_error(501, "Not Implemented", "Unsupported container create options: " + unsupported);
    for (const char* key : {"AttachStdout", "AttachStderr"}) {
        if (input.contains(key) && !input[key].is_boolean() && !input[key].is_null())
            return http_error(400, "Bad Request", std::string("Invalid ") + key);
    }
    if (!input.contains("Image") || !input["Image"].is_string() || !input.contains("Cmd") || !input["Cmd"].is_array())
        return http_error(400, "Bad Request", "Image and Cmd are required");
    json request = {{"name", name}, {"image", input["Image"]}, {"command", input["Cmd"]}};
    for (const char* field : {"Hostname", "Domainname"}) {
        if (!input.contains(field) || input[field].is_null()) continue;
        if (!input[field].is_string()) return http_error(400, "Bad Request", std::string("Invalid ") + field);
        const std::string value = input[field].get<std::string>();
        if (!value.empty() && (!safe_dns_name(value) || (std::string(field) == "Hostname" && value.find('.') != std::string::npos)))
            return http_error(400, "Bad Request", std::string("Invalid ") + field);
        request[std::string(field) == "Hostname" ? "hostname" : "domainname"] = value;
    }
    if (input.contains("NetworkingConfig") && !input["NetworkingConfig"].is_null()) {
        const auto& networking = input["NetworkingConfig"];
        if (!networking.is_object()) return http_error(400, "Bad Request", "Invalid NetworkingConfig");
        for (auto it = networking.begin(); it != networking.end(); ++it) {
            if (it.key() != "EndpointsConfig" && !empty_json_value(it.value()))
                return http_error(501, "Not Implemented", "Unsupported NetworkingConfig option: " + it.key());
        }
        if (networking.contains("EndpointsConfig") && !empty_json_value(networking["EndpointsConfig"])) {
            const auto& endpoints = networking["EndpointsConfig"];
            if (!endpoints.is_object()) return http_error(400, "Bad Request", "Invalid EndpointsConfig");
            if (endpoints.size() != 1 || (!endpoints.contains("default") && !endpoints.contains("bridge")))
                return http_error(501, "Not Implemented", "Custom network endpoints are unsupported");
            for (auto it = endpoints.begin(); it != endpoints.end(); ++it) {
                if (!it.value().is_object()) return http_error(400, "Bad Request", "Invalid default network endpoint");
                for (auto field = it.value().begin(); field != it.value().end(); ++field)
                    if (!empty_json_value(field.value()))
                        return http_error(501, "Not Implemented", "Unsupported network endpoint option: " + field.key());
            }
            if (request.value("network", "") == "none")
                return http_error(400, "Bad Request", "Default network endpoint conflicts with none mode");
            request["network"] = "bridge";
        }
    }
    if (input.contains("Env") && !input["Env"].is_null()) request["env"] = input["Env"];
    if (input.contains("WorkingDir") && !input["WorkingDir"].is_null()) request["workdir"] = input["WorkingDir"];
    if (input.contains("ExposedPorts") && !input["ExposedPorts"].is_null()) {
        const auto& exposed = input["ExposedPorts"];
        if (!exposed.is_object() || exposed.size() > 32) return http_error(400, "Bad Request", "Invalid ExposedPorts");
        for (auto it = exposed.begin(); it != exposed.end(); ++it) {
            int port = 0;
            std::string protocol;
            if (!container_port_key(it.key(), port, protocol) || !empty_json_value(it.value()))
                return http_error(400, "Bad Request", "Invalid exposed port");
        }
        if (!exposed.empty()) request["network"] = "bridge";
    }
    if (input.contains("HostConfig") && !input["HostConfig"].is_null()) {
        const auto& host = input["HostConfig"];
        if (!host.is_object()) return http_error(400, "Bad Request", "Invalid HostConfig");
        std::string unsupported_host;
        for (auto it = host.begin(); it != host.end(); ++it) {
            if (it.key() != "Privileged" && it.key() != "NetworkMode" && it.key() != "PortBindings"
                && it.key() != "ConsoleSize"
                && it.key() != "LogConfig" && it.key() != "MemorySwappiness" && it.key() != "RestartPolicy"
                && it.key() != "Binds" && !empty_json_value(it.value()))
                unsupported_host += (unsupported_host.empty() ? "" : ", ") + it.key();
        }
        if (!unsupported_host.empty()) return http_error(501, "Not Implemented", "Unsupported HostConfig options: " + unsupported_host);
        if (host.contains("Privileged") && host["Privileged"] != false && !host["Privileged"].is_null())
            return http_error(501, "Not Implemented", "Privileged containers are unsupported");
        if (host.contains("ConsoleSize") && !host["ConsoleSize"].is_null()) {
            const auto& size = host["ConsoleSize"];
            if (!size.is_array() || size.size() != 2 || !size[0].is_number_integer() || !size[1].is_number_integer())
                return http_error(400, "Bad Request", "Invalid console size");
            if (size[0] != 0 || size[1] != 0)
                return http_error(501, "Not Implemented", "Custom console size is unsupported");
        }
        if (host.contains("LogConfig") && !host["LogConfig"].is_null()) {
            const auto& log = host["LogConfig"];
            if (!log.is_object()) return http_error(400, "Bad Request", "Invalid LogConfig");
            for (auto it = log.begin(); it != log.end(); ++it)
                if (it.key() != "Type" && it.key() != "Config" && !empty_json_value(it.value()))
                    return http_error(501, "Not Implemented", "Unsupported LogConfig option: " + it.key());
            if ((log.contains("Type") && !empty_json_value(log["Type"]))
                || (log.contains("Config") && !empty_json_value(log["Config"])))
                return http_error(501, "Not Implemented", "Custom logging configuration is unsupported");
        }
        if (host.contains("MemorySwappiness") && !host["MemorySwappiness"].is_null()) {
            if (!host["MemorySwappiness"].is_number_integer()) return http_error(400, "Bad Request", "Invalid MemorySwappiness");
            if (host["MemorySwappiness"] != -1 && host["MemorySwappiness"] != 0)
                return http_error(501, "Not Implemented", "Custom memory swappiness is unsupported");
        }
        if (host.contains("RestartPolicy") && !host["RestartPolicy"].is_null()) {
            const auto& policy = host["RestartPolicy"];
            if (!policy.is_object()) return http_error(400, "Bad Request", "Invalid RestartPolicy");
            for (auto it = policy.begin(); it != policy.end(); ++it)
                if (it.key() != "Name" && it.key() != "MaximumRetryCount" && !empty_json_value(it.value()))
                    return http_error(501, "Not Implemented", "Unsupported RestartPolicy option: " + it.key());
            if ((policy.contains("Name") && policy["Name"] != "" && policy["Name"] != "no")
                || (policy.contains("MaximumRetryCount") && policy["MaximumRetryCount"] != 0))
                return http_error(501, "Not Implemented", "Automatic restart policy is unsupported");
        }
        if (host.contains("NetworkMode") && !host["NetworkMode"].is_null()) {
            if (!host["NetworkMode"].is_string()) return http_error(400, "Bad Request", "Invalid network mode");
            const std::string mode = host["NetworkMode"].get<std::string>();
            if (mode != "" && mode != "default" && mode != "bridge" && mode != "none")
                return http_error(501, "Not Implemented", "Unsupported network mode");
            if (mode == "none" && request.value("network", "") == "bridge")
                return http_error(400, "Bad Request", "Exposed ports require bridged networking");
            if (mode != "") request["network"] = mode == "none" ? "none" : "bridge";
        }
        if (host.contains("PortBindings") && !host["PortBindings"].is_null()) {
            const auto& bindings = host["PortBindings"];
            if (!bindings.is_object() || bindings.size() > 32) return http_error(400, "Bad Request", "Invalid PortBindings");
            json ports = json::array();
            for (auto it = bindings.begin(); it != bindings.end(); ++it) {
                int target = 0;
                std::string protocol;
                if (!container_port_key(it.key(), target, protocol) || !it.value().is_array() || it.value().size() != 1
                    || !it.value()[0].is_object()) return http_error(400, "Bad Request", "Invalid port binding");
                const auto& binding = it.value()[0];
                for (auto field = binding.begin(); field != binding.end(); ++field) {
                    if (field.key() != "HostIp" && field.key() != "HostPort" && !empty_json_value(field.value()))
                        return http_error(501, "Not Implemented", "Unsupported port binding option");
                }
                if (!binding.value("HostPort", json()).is_string() || !binding.value("HostIp", json("")).is_string())
                    return http_error(400, "Bad Request", "Invalid host port or address");
                const std::string host_ip = binding.value("HostIp", "");
                const int host_port = decimal_port(binding.value("HostPort", ""));
                if (host_port == 0 || (host_ip != "" && host_ip != "127.0.0.1"))
                    return http_error(501, "Not Implemented", "Only explicit loopback host ports are supported");
                ports.push_back({{"host", host_port}, {"container", target}, {"protocol", protocol}});
            }
            if (request.value("network", "") == "none" && !ports.empty())
                return http_error(400, "Bad Request", "Port bindings require bridged networking");
            request["ports"] = std::move(ports);
            if (!request["ports"].empty()) request["network"] = "bridge";
        }
        if (host.contains("Binds") && !host["Binds"].is_null()) {
            const auto& binds = host["Binds"];
            if (!binds.is_array() || binds.size() > 32) return http_error(400, "Bad Request", "Invalid Binds");
            json volumes = json::array();
            for (const auto& bind : binds) {
                if (!bind.is_string()) return http_error(400, "Bad Request", "Invalid volume binding");
                const std::string value = bind.get<std::string>();
                const size_t first = value.find(':');
                const size_t second = first == std::string::npos ? first : value.find(':', first + 1);
                if (first == std::string::npos || value.find(':', second == std::string::npos ? value.size() : second + 1) != std::string::npos)
                    return http_error(400, "Bad Request", "Invalid volume binding");
                const std::string source = value.substr(0, first);
                const std::string target = value.substr(first + 1, second == std::string::npos ? std::string::npos : second - first - 1);
                const std::string mode = second == std::string::npos ? "rw" : value.substr(second + 1);
                if (!safe_name(source)) return http_error(501, "Not Implemented", "Only named volumes are supported");
                if (target.empty() || target[0] != '/' || (mode != "ro" && mode != "rw"))
                    return http_error(400, "Bad Request", "Invalid volume target or mode");
                volumes.push_back({{"name", source}, {"path", target}, {"readonly", mode == "ro"}});
            }
            request["volumes"] = std::move(volumes);
        }
    }
    const json result = create_container(session, request);
    if (!result.value("ok", false)) return http_error(400, "Bad Request", result.value("error", "Container creation failed"));
    return http_reply(201, "Created", json({{"Id", result.at("id")}, {"Warnings", json::array()}}).dump());
}

static std::string http_container_logs(const std::wstring& session_name, const std::string& name, const std::string& query) {
    bool stdout_requested = false, stderr_requested = false, timestamps = false, details = false;
    std::string tail = "all";
    std::string since, until;
    bool seen_stdout = false, seen_stderr = false, seen_tail = false, seen_timestamps = false;
    bool seen_since = false, seen_until = false, seen_details = false, seen_follow = false;
    for (size_t cursor = 0; cursor < query.size();) {
        const size_t end = query.find('&', cursor);
        const std::string part = query.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
        const size_t equal = part.find('=');
        if (equal == std::string::npos) return http_error(400, "Bad Request", "Invalid logs query");
        const std::string key = part.substr(0, equal);
        const std::string value = part.substr(equal + 1);
        if (key == "stdout" && !seen_stdout && (value == "0" || value == "1" || value == "true" || value == "false")) {
            stdout_requested = value == "1" || value == "true";
            seen_stdout = true;
        } else if (key == "stderr" && !seen_stderr && (value == "0" || value == "1" || value == "true" || value == "false")) {
            stderr_requested = value == "1" || value == "true";
            seen_stderr = true;
        } else if (key == "timestamps" && !seen_timestamps && (value == "0" || value == "1" || value == "true" || value == "false")) {
            timestamps = value == "1" || value == "true";
            seen_timestamps = true;
        } else if (key == "tail" && !seen_tail && (value == "all" || value == "0" || (value.size() <= 5 && decimal_port(value)))) {
            tail = value;
            seen_tail = true;
        } else if (key == "details" && !seen_details && (value == "0" || value == "1" || value == "true" || value == "false")) {
            details = value == "1" || value == "true";
            seen_details = true;
        } else if (key == "follow" && !seen_follow && (value == "0" || value == "false")) {
            seen_follow = true;
        } else if (key == "since" && !seen_since && (value.empty() || log_time_value(value, since))) {
            seen_since = true;
        } else if (key == "until" && !seen_until && (value.empty() || log_time_value(value, until))) {
            seen_until = true;
        } else return http_error(501, "Not Implemented", "Unsupported logs query option: " + key);
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    if (stdout_requested != stderr_requested)
        return http_error(501, "Not Implemented", "Separate stdout and stderr logs are unsupported");
    if (!stdout_requested && !stderr_requested) return http_reply(200, "OK", "", "application/vnd.docker.raw-stream");
    if (tail == "0") return http_reply(200, "OK", "", "application/vnd.docker.raw-stream");
    std::wstring arguments = L"container logs --tail " + std::wstring(tail.begin(), tail.end());
    if (timestamps) arguments += L" --timestamps";
    if (details) arguments += L" --details";
    if (!since.empty()) arguments += L" --since " + std::wstring(since.begin(), since.end());
    if (!until.empty()) arguments += L" --until " + std::wstring(until.begin(), until.end());
    arguments += L" " + std::wstring(name.begin(), name.end());
    std::string raw;
    bool read = false;
    for (int attempt = 0; attempt < 8; ++attempt) {
        raw.clear();
        if (run_wslc_command(session_name, arguments, raw, 256 * 1024, 15000)) { read = true; break; }
        if (attempt < 7) Sleep(250);
    }
    if (!read)
        return http_error(500, "Internal Server Error", "Cannot read container logs or log output exceeds 256 KB");
    std::string framed;
    framed.reserve(raw.size() + (raw.size() / 16384 + 1) * 8);
    for (size_t offset = 0; offset < raw.size();) {
        const uint32_t size = static_cast<uint32_t>(std::min<size_t>(16384, raw.size() - offset));
        const char header[8] = {1, 0, 0, 0, static_cast<char>(size >> 24), static_cast<char>(size >> 16),
            static_cast<char>(size >> 8), static_cast<char>(size)};
        framed.append(header, sizeof(header));
        framed.append(raw, offset, size);
        offset += size;
    }
    return http_reply(200, "OK", framed, "application/vnd.docker.raw-stream");
}

static std::string http_pull_image(WslcSession session, const std::string& query) {
    std::string image, tag;
    bool seen_image = false, seen_tag = false;
    for (size_t cursor = 0; cursor < query.size();) {
        const size_t end = query.find('&', cursor);
        const std::string item = query.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
        const size_t equal = item.find('=');
        if (equal == std::string::npos) return http_error(400, "Bad Request", "Invalid image pull query");
        const std::string key = item.substr(0, equal);
        const std::string encoded = item.substr(equal + 1);
        std::string value;
        for (size_t index = 0; index < encoded.size(); ++index) {
            if (encoded[index] == '%') {
                if (index + 2 >= encoded.size()) return http_error(400, "Bad Request", "Invalid image pull encoding");
                const int high = hex_digit(encoded[index + 1]);
                const int low = hex_digit(encoded[index + 2]);
                if (high < 0 || low < 0) return http_error(400, "Bad Request", "Invalid image pull encoding");
                value.push_back(static_cast<char>(high * 16 + low));
                index += 2;
            } else value.push_back(encoded[index]);
        }
        if (key == "fromImage" && !seen_image) { image = value; seen_image = true; }
        else if (key == "tag" && !seen_tag) { tag = value; seen_tag = true; }
        else return http_error(400, "Bad Request", "Unsupported image pull query");
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    if (!safe_image_reference(image) || (!tag.empty() && !safe_image_reference(tag)) || tag.find('/') != std::string::npos
        || (!tag.empty() && image.find('@') != std::string::npos))
        return http_error(400, "Bad Request", "Invalid image reference or tag");
    if (!tag.empty() && image.find(':', image.find_last_of('/') == std::string::npos ? 0 : image.find_last_of('/')) != std::string::npos)
        return http_error(400, "Bad Request", "Image reference already has a tag");
    const std::string reference = tag.empty() ? image : image + ":" + tag;
    WslcPullImageOptions options = {};
    options.uri = reference.c_str();
    PWSTR error = nullptr;
    const HRESULT pulled = WslcPullSessionImage(session, &options, &error);
    if (error) CoTaskMemFree(error);
    if (FAILED(pulled)) return http_error(500, "Internal Server Error", "Image pull failed");
    return http_reply(200, "OK", json({{"status", "Pull complete"}}).dump() + "\n", "application/x-ndjson");
}

static std::string http_tag_image(WslcSession session, const std::string& reference, const std::string& query) {
    if (!safe_image_reference(reference)) return http_error(400, "Bad Request", "Invalid source image");
    std::string repo, tag;
    bool seen_repo = false, seen_tag = false;
    for (size_t cursor = 0; cursor < query.size();) {
        const size_t end = query.find('&', cursor);
        const std::string item = query.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
        const size_t equal = item.find('=');
        if (equal == std::string::npos) return http_error(400, "Bad Request", "Invalid image tag query");
        const std::string key = item.substr(0, equal);
        const std::string encoded = item.substr(equal + 1);
        std::string value;
        for (size_t index = 0; index < encoded.size(); ++index) {
            if (encoded[index] == '%') {
                if (index + 2 >= encoded.size()) return http_error(400, "Bad Request", "Invalid image tag encoding");
                const int high = hex_digit(encoded[index + 1]);
                const int low = hex_digit(encoded[index + 2]);
                if (high < 0 || low < 0) return http_error(400, "Bad Request", "Invalid image tag encoding");
                value.push_back(static_cast<char>(high * 16 + low));
                index += 2;
            } else value.push_back(encoded[index]);
        }
        if (key == "repo" && !seen_repo) { repo = value; seen_repo = true; }
        else if (key == "tag" && !seen_tag) { tag = value; seen_tag = true; }
        else return http_error(400, "Bad Request", "Unsupported image tag query");
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    const size_t final_slash = repo.find_last_of('/');
    if (!safe_image_reference(repo) || !safe_name(tag) || tag.size() > 128 || tag.find('.') == 0
        || repo.find('@') != std::string::npos
        || repo.find(':', final_slash == std::string::npos ? 0 : final_slash + 1) != std::string::npos)
        return http_error(400, "Bad Request", "Invalid image repository or tag");
    const WslcTagImageOptions options = {reference.c_str(), repo.c_str(), tag.c_str()};
    PWSTR error = nullptr;
    const HRESULT tagged = WslcTagSessionImage(session, &options, &error);
    if (error) CoTaskMemFree(error);
    if (FAILED(tagged)) return http_error(404, "Not Found", "Source image was not found or could not be tagged");
    return http_reply(201, "Created", "");
}

static std::string http_delete_image(WslcSession session, const std::string& reference, const std::string& query) {
    if (!safe_image_reference(reference)) return http_error(400, "Bad Request", "Invalid image reference");
    bool seen_force = false, seen_noprune = false;
    for (size_t cursor = 0; cursor < query.size();) {
        const size_t end = query.find('&', cursor);
        const std::string item = query.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
        if (item == "force=false" && !seen_force) seen_force = true;
        else if (item == "noprune=false" && !seen_noprune) seen_noprune = true;
        else return http_error(501, "Not Implemented", "Unsupported image removal option");
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    PWSTR error = nullptr;
    const HRESULT deleted = WslcDeleteSessionImage(session, reference.c_str(), &error);
    if (error) CoTaskMemFree(error);
    if (FAILED(deleted)) return http_error(409, "Conflict", "Image could not be removed");
    return http_reply(200, "OK", json::array({{{"Untagged", reference}}}).dump());
}

static std::string http_wait_container(WslcSession session, const std::string& name) {
    WslcContainer container = nullptr;
    PWSTR error = nullptr;
    const HRESULT opened = WslcOpenContainer(session, name.c_str(), &container, &error);
    if (error) CoTaskMemFree(error);
    if (FAILED(opened)) return http_error(404, "Not Found", "Container not found");
    WslcContainerState state = WSLC_CONTAINER_STATE_INVALID;
    const HRESULT state_result = WslcGetContainerState(container, &state);
    if (FAILED(state_result)) { WslcReleaseContainer(container); return http_error(500, "Internal Server Error", "Cannot read container state"); }
    if (state == WSLC_CONTAINER_STATE_CREATED) {
        WslcReleaseContainer(container);
        return http_reply(200, "OK", json({{"StatusCode", 0}}).dump());
    }
    WslcProcess init_process = nullptr;
    const HRESULT process_result = WslcGetContainerInitProcess(container, &init_process);
    if (FAILED(process_result) || !init_process) {
        WslcReleaseContainer(container);
        return http_error(500, "Internal Server Error", "Cannot read container init process");
    }
    if (state == WSLC_CONTAINER_STATE_RUNNING) {
        HANDLE exit_event = nullptr;
        if (FAILED(WslcGetProcessExitEvent(init_process, &exit_event)) || !exit_event) {
            WslcReleaseProcess(init_process);
            WslcReleaseContainer(container);
            return http_error(500, "Internal Server Error", "Cannot wait for container exit");
        }
        const DWORD waited = WaitForSingleObject(exit_event, 60000);
        if (waited != WAIT_OBJECT_0) {
            WslcReleaseProcess(init_process);
            WslcReleaseContainer(container);
            return http_error(waited == WAIT_TIMEOUT ? 503 : 500, waited == WAIT_TIMEOUT ? "Service Unavailable" : "Internal Server Error",
                waited == WAIT_TIMEOUT ? "Container wait exceeded 60 seconds" : "Container wait failed");
        }
    }
    INT32 exit_code = 0;
    const HRESULT code_result = WslcGetProcessExitCode(init_process, &exit_code);
    WslcReleaseProcess(init_process);
    WslcReleaseContainer(container);
    if (FAILED(code_result)) return http_error(500, "Internal Server Error", "Cannot read container exit code");
    return http_reply(200, "OK", json({{"StatusCode", exit_code}}).dump());
}

static std::string handle_http(WslcSession session, const std::wstring& session_name, const std::string& request) {
    const auto line_end = request.find("\r\n");
    if (line_end == std::string::npos || line_end > 2048) return http_error(400, "Bad Request", "Invalid request line");
    const std::string line = request.substr(0, line_end);
    const auto first_space = line.find(' ');
    const auto last_space = line.rfind(' ');
    if (first_space == std::string::npos || last_space == first_space || line.substr(last_space + 1) != "HTTP/1.1")
        return http_error(400, "Bad Request", "Invalid HTTP request");
    const std::string method = line.substr(0, first_space);
    std::string path = line.substr(first_space + 1, last_space - first_space - 1);
    if (path.empty() || path[0] != '/' || path.find('#') != std::string::npos)
        return http_error(400, "Bad Request", "Invalid API path");
    const size_t header_end = request.find("\r\n\r\n");
    size_t body_length = 0;
    if (header_end == std::string::npos || !http_body_length(request, header_end, body_length)
        || request.size() != header_end + 4 + body_length)
        return http_error(400, "Bad Request", "Invalid HTTP body length or headers");
    const std::string body = request.substr(header_end + 4);
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
    if (path == "/info" && method == "GET") {
        const json containers = list_session_containers(session, session_name, true);
        const json images = list_session_images(session);
        if (!containers.value("ok", false) || !images.value("ok", false))
            return http_error(503, "Service Unavailable", "Cannot read engine inventory");
        size_t running = 0, paused = 0, stopped = 0;
        for (const auto& container : containers.at("containers")) {
            const std::string state = container.value("State", "");
            if (state == "running") ++running;
            else if (state == "paused") ++paused;
            else ++stopped;
        }
        const json info = {{"ID", ""}, {"Name", "Omnark Engine"}, {"ServerVersion", "0.1.0-omnark"},
            {"OSType", "linux"}, {"Architecture", "x86_64"}, {"OperatingSystem", "WSL Containers"},
            {"Driver", "wsl-containers"}, {"Containers", containers.at("containers").size()},
            {"ContainersRunning", running}, {"ContainersPaused", paused}, {"ContainersStopped", stopped},
            {"Images", images.at("images").size()}, {"ExperimentalBuild", false},
            {"Warnings", json::array({"Omnark implements a subset of the Docker Engine API"})}};
        return http_reply(200, "OK", info.dump());
    }
    if (path == "/images/json" && method == "GET") {
        const json result = list_session_images(session);
        if (!result.value("ok", false)) return http_error(500, "Internal Server Error", result.value("error", "Image list failed"));
        const std::string body = result.at("images").dump();
        return body.size() <= 60000 ? http_reply(200, "OK", body)
            : http_error(500, "Internal Server Error", "Image list exceeds response limit");
    }
    constexpr const char* pull_prefix = "/images/create?";
    if (method == "POST" && path.rfind(pull_prefix, 0) == 0)
        return http_pull_image(session, path.substr(std::strlen(pull_prefix)));
    constexpr const char* image_prefix = "/images/";
    constexpr const char* image_suffix = "/json";
    if (method == "DELETE" && path.rfind(image_prefix, 0) == 0) {
        const size_t query_at = path.find('?', std::strlen(image_prefix));
        const std::string reference = path.substr(std::strlen(image_prefix), query_at == std::string::npos ? std::string::npos : query_at - std::strlen(image_prefix));
        return http_delete_image(session, reference, query_at == std::string::npos ? "" : path.substr(query_at + 1));
    }
    if (method == "POST" && path.rfind(image_prefix, 0) == 0) {
        const size_t tag_at = path.find("/tag?", std::strlen(image_prefix));
        if (tag_at != std::string::npos) {
            const std::string reference = path.substr(std::strlen(image_prefix), tag_at - std::strlen(image_prefix));
            return http_tag_image(session, reference, path.substr(tag_at + std::strlen("/tag?")));
        }
    }
    if (method == "GET" && path.rfind(image_prefix, 0) == 0
        && path.size() > std::strlen(image_prefix) + std::strlen(image_suffix)
        && path.compare(path.size() - std::strlen(image_suffix), std::strlen(image_suffix), image_suffix) == 0) {
        const std::string reference = path.substr(std::strlen(image_prefix),
            path.size() - std::strlen(image_prefix) - std::strlen(image_suffix));
        if (!safe_image_reference(reference)) return http_error(400, "Bad Request", "Invalid image reference");
        std::string output;
        const std::wstring args = L"image inspect --format json " + std::wstring(reference.begin(), reference.end());
        bool inspected = false;
        for (int attempt = 0; attempt < 8; ++attempt) {
            output.clear();
            if (run_wslc_command(session_name, args, output, 60000, 15000)) { inspected = true; break; }
            if (attempt < 7) Sleep(250);
        }
        if (!inspected)
            return http_error(404, "Not Found", "Image inspection failed or image was not found");
        const json parsed = json::parse(output, nullptr, false);
        if (!parsed.is_array() || parsed.size() != 1 || !parsed[0].is_object())
            return http_error(502, "Bad Gateway", "Invalid image inspection response");
        const std::string body = parsed[0].dump();
        return body.size() <= 60000 ? http_reply(200, "OK", body)
            : http_error(502, "Bad Gateway", "Image inspection response exceeds limit");
    }
    if (method == "GET" && (path == "/containers/json" || path.rfind("/containers/json?", 0) == 0)) {
        bool all = false;
        bool seen_all = false, seen_size = false;
        const size_t query = path.find('?');
        for (size_t cursor = query == std::string::npos ? path.size() : query + 1; cursor < path.size();) {
            const size_t end = path.find('&', cursor);
            const std::string part = path.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor);
            const size_t equal = part.find('=');
            if (equal == std::string::npos) return http_error(400, "Bad Request", "Invalid container list query");
            const std::string key = part.substr(0, equal);
            const std::string value = part.substr(equal + 1);
            if (key == "all" && !seen_all && (value == "0" || value == "1" || value == "true" || value == "false")) {
                all = value == "1" || value == "true";
                seen_all = true;
            } else if (key == "size" && !seen_size && (value == "0" || value == "1" || value == "true" || value == "false")) {
                seen_size = true;
            } else return http_error(400, "Bad Request", "Unsupported container list query");
            if (end == std::string::npos) break;
            cursor = end + 1;
        }
        const json result = list_session_containers(session, session_name, all);
        if (!result.value("ok", false)) return http_error(500, "Internal Server Error", result.value("error", "Container list failed"));
        const std::string rows = result.at("containers").dump();
        return rows.size() <= 60000 ? http_reply(200, "OK", rows)
            : http_error(500, "Internal Server Error", "Container list exceeds response limit");
    }
    if (method == "POST" && (path == "/containers/prune" || path == "/containers/prune?filters=%7B%7D")) {
        const json listed = list_session_containers(session, session_name, true);
        if (!listed.value("ok", false)) return http_error(503, "Service Unavailable", "Cannot list session containers");
        json removed = json::array();
        for (const auto& row : listed.at("containers")) {
            if (row.value("State", "") == "running") continue;
            const std::string id = row.value("Id", "");
            if (!safe_name(id)) return http_error(502, "Bad Gateway", "Invalid listed container ID");
            const json inspected = manage_container(session, {{"name", id}}, "inspect");
            if (!inspected.value("ok", false)) return http_error(500, "Internal Server Error", "Cannot inspect container before pruning");
            const json state = inspected.at("inspect").value("State", json::object());
            if (!state.is_object() || !state.contains("Running") || !state.at("Running").is_boolean())
                return http_error(502, "Bad Gateway", "Invalid container state before pruning");
            if (state.at("Running").get<bool>()) continue;
            const json deleted = manage_container(session, {{"name", id}}, "remove");
            if (!deleted.value("ok", false)) return http_error(500, "Internal Server Error", "Container prune was incomplete");
            removed.push_back(id);
        }
        return http_reply(200, "OK", json({{"ContainersDeleted", std::move(removed)}, {"SpaceReclaimed", 0}}).dump());
    }
    constexpr const char* create_prefix = "/containers/create?name=";
    if (method == "POST" && path.compare(0, std::strlen(create_prefix), create_prefix) == 0)
        return http_create_container(session, path.substr(std::strlen(create_prefix)), body);
    constexpr const char* logs_infix = "/logs?";
    if (method == "GET" && path.rfind("/containers/", 0) == 0) {
        const size_t top_at = path.find("/top", std::strlen("/containers/"));
        if (top_at != std::string::npos && path.substr(top_at) == "/top") {
            const std::string name = path.substr(std::strlen("/containers/"), top_at - std::strlen("/containers/"));
            if (!safe_name(name)) return http_error(400, "Bad Request", "Invalid container name or ID");
            const json found = manage_container(session, {{"name", name}}, "inspect");
            if (!found.value("ok", false)) return http_error(404, "Not Found", "Container not found");
            if (!found.at("inspect").at("State").value("Running", false))
                return http_error(409, "Conflict", "Container is not running");
            std::string output;
            const std::wstring arguments = L"container exec " + std::wstring(name.begin(), name.end()) + L" ps -o pid,user,args";
            if (!run_wslc_command(session_name, arguments, output, 60000, 15000))
                return http_error(501, "Not Implemented", "Process listing requires ps in the container image");
            json rows = json::array();
            std::istringstream lines(output);
            std::string line;
            bool header = true;
            while (std::getline(lines, line)) {
                if (header) { header = false; continue; }
                std::istringstream fields(line);
                std::string pid, user;
                if (!(fields >> pid >> user)) continue;
                std::string command;
                std::getline(fields >> std::ws, command);
                if (!command.empty()) rows.push_back({pid, user, command});
            }
            return http_reply(200, "OK", json({{"Titles", {"PID", "USER", "COMMAND"}}, {"Processes", rows}}).dump());
        }
        const size_t logs_at = path.find(logs_infix, std::strlen("/containers/"));
        if (logs_at != std::string::npos) {
            const std::string name = path.substr(std::strlen("/containers/"), logs_at - std::strlen("/containers/"));
            if (!safe_name(name)) return http_error(400, "Bad Request", "Invalid container name or ID");
            const json found = manage_container(session, {{"name", name}}, "inspect");
            if (!found.value("ok", false)) return http_error(404, "Not Found", "Container not found");
            return http_container_logs(session_name, name, path.substr(logs_at + std::strlen(logs_infix)));
        }
    }
    if (method == "POST" && path.rfind("/containers/", 0) == 0) {
        const size_t wait_at = path.find("/wait", std::strlen("/containers/"));
        if (wait_at != std::string::npos) {
            const std::string name = path.substr(std::strlen("/containers/"), wait_at - std::strlen("/containers/"));
            const std::string options = path.substr(wait_at + std::strlen("/wait"));
            if (!safe_name(name)) return http_error(400, "Bad Request", "Invalid container name or ID");
            if (options != "" && options != "?condition=not-running" && options != "?condition=")
                return http_error(400, "Bad Request", "Unsupported container wait condition");
            return http_wait_container(session, name);
        }
    }
    if (path.find('?') != std::string::npos) return http_error(400, "Bad Request", "Unsupported API query");
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
        else if (method == "POST" && suffix == "/restart") op = "restart";
        else if (method == "POST" && suffix == "/kill") op = "kill";
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

static int serve_http_pipe(WslcSession session, HANDLE stop, HANDLE terminated, const std::wstring& pipe_name, const std::wstring& session_name) {
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
        while (request.size() < 24576 && request.find("\r\n\r\n") == std::string::npos) {
            if (!pipe_io(pipe, false, buffer, sizeof(buffer), received, stop, terminated) || received == 0) break;
            request.append(buffer, received);
        }
        const size_t header_end = request.find("\r\n\r\n");
        size_t body_length = 0;
        const bool valid_headers = header_end != std::string::npos && header_end <= 8192
            && http_body_length(request, header_end, body_length);
        if (valid_headers) {
            const size_t expected = header_end + 4 + body_length;
            while (request.size() < expected && request.size() < 24576) {
                if (!pipe_io(pipe, false, buffer, static_cast<DWORD>(std::min(sizeof(buffer), expected - request.size())), received, stop, terminated) || received == 0) break;
                request.append(buffer, received);
            }
        }
        std::string response;
        try {
            response = !valid_headers ? http_error(400, "Bad Request", "Invalid HTTP headers") : handle_http(session, session_name, request);
        } catch (...) {
            response = http_error(500, "Internal Server Error", "Engine API request failed");
        }
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
                    else if (op == "images") response = list_session_images(session);
                    else if (op == "inspect" || op == "start" || op == "stop" || op == "restart" || op == "kill" || op == "remove") response = manage_container(session, request, op);
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
                http_result = serve_http_pipe(session, stop_event, terminated, http_pipe_name, session_name);
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

