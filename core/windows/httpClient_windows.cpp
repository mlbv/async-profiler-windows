/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include <winhttp.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <cwctype>
#include <string>
#include "httpClient.h"
#include "log.h"
#include "writer.h"

namespace {
constexpr DWORD HTTP_TIMEOUT_MS = 10000;
constexpr size_t MAX_RESPONSE_SIZE = 4 * 1024 * 1024;

std::wstring httpEnv(const wchar_t* name) {
    std::wstring result(32768, L'\0');
    DWORD length = GetEnvironmentVariableW(name, result.data(), static_cast<DWORD>(result.size()));
    result.resize(length);
    return result;
}

bool httpCredential(const wchar_t* text, DWORD length, std::wstring& result) {
    std::string encoded = WindowsProfiler::utf8(std::wstring_view(text, length));
    std::string decoded;
    auto hex = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i < encoded.size(); i++) {
        char c = encoded[i];
        if (c == '%' && i + 2 < encoded.size()) {
            int high = hex(encoded[i + 1]), low = hex(encoded[i + 2]);
            if (high >= 0 && low >= 0) {
                c = static_cast<char>(high * 16 + low);
                i += 2;
            }
        }
        if (c == 0) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
        decoded += c;
    }
    result = WindowsProfiler::wide(decoded);
    if ((!decoded.empty() && result.empty()) || (length != 0 && encoded.empty())) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return false;
    }
    return true;
}

bool httpBypass(std::wstring host, const std::wstring& bypass) {
    if (!host.empty() && host.front() == L'[' && host.back() == L']') {
        host = host.substr(1, host.size() - 2);
    }
    if (!host.empty() && host.back() == L'.') host.pop_back();
    std::transform(host.begin(), host.end(), host.begin(), towlower);
    for (size_t begin = 0; begin < bypass.size();) {
        size_t end = bypass.find(L',', begin);
        if (end == std::wstring::npos) end = bypass.size();
        std::wstring entry = bypass.substr(begin, end - begin);
        begin = end + 1;
        size_t first = entry.find_first_not_of(L" \t");
        if (first == std::wstring::npos) continue;
        entry = entry.substr(first, entry.find_last_not_of(L" \t") - first + 1);
        if (entry == L"*") return true;
        std::transform(entry.begin(), entry.end(), entry.begin(), towlower);
        size_t slash = entry.find(L'/');
        if (slash != std::wstring::npos) {
            wchar_t* suffix;
            unsigned long bits = wcstoul(entry.c_str() + slash + 1, &suffix, 10);
            std::wstring network = entry.substr(0, slash);
            unsigned char address[16], subnet[16];
            int family = host.find(L':') == std::wstring::npos ? AF_INET : AF_INET6;
            unsigned int width = family == AF_INET ? 32 : 128;
            if (suffix != entry.c_str() + slash + 1 && *suffix == 0 && bits <= width &&
                    InetPtonW(family, host.c_str(), address) == 1 &&
                    InetPtonW(family, network.c_str(), subnet) == 1) {
                size_t bytes = bits / 8;
                unsigned int rest = bits % 8;
                if (memcmp(address, subnet, bytes) == 0 &&
                        (rest == 0 || ((address[bytes] ^ subnet[bytes]) & (0xff << (8 - rest))) == 0)) {
                    return true;
                }
            }
        } else {
            if (entry.front() == L'.') entry.erase(0, 1);
            if (!entry.empty() && entry.back() == L'.') entry.pop_back();
            if (host == entry || (host.size() > entry.size() &&
                    host.compare(host.size() - entry.size(), entry.size(), entry) == 0 &&
                    host[host.size() - entry.size() - 1] == L'.')) return true;
        }
    }
    return false;
}

class HttpRequest {
    HINTERNET _session = nullptr;
    HINTERNET _connection = nullptr;
    HINTERNET _request = nullptr;
    HANDLE _completed = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    HANDLE _closed = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    bool _callback = false;
    ULONGLONG _deadline = GetTickCount64() + HTTP_TIMEOUT_MS;
    DWORD _error = ERROR_SUCCESS;
    std::atomic<DWORD> _operation_error{ERROR_SUCCESS};
    DWORD _read = 0;
    char _buffer[8192];

    static void CALLBACK status(HINTERNET, DWORD_PTR context, DWORD status, void* info, DWORD length) {
        auto* self = reinterpret_cast<HttpRequest*>(context);
        if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
            SetEvent(self->_closed);
        } else if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
            self->_operation_error.store(static_cast<WINHTTP_ASYNC_RESULT*>(info)->dwError, std::memory_order_release);
            SetEvent(self->_completed);
        } else if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
            self->_read = length;
            SetEvent(self->_completed);
        } else if (status == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE ||
                status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE ||
                status == WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE) {
            SetEvent(self->_completed);
        }
    }

    bool finish(BOOL started) {
        if (!started) {
            DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) {
                _error = error;
                return false;
            }
        }
        ULONGLONG now = GetTickCount64();
        DWORD wait = WaitForSingleObject(_completed, now < _deadline ? static_cast<DWORD>(_deadline - now) : 0);
        if (wait != WAIT_OBJECT_0) {
            _error = wait == WAIT_TIMEOUT ? ERROR_WINHTTP_TIMEOUT : GetLastError();
            return false;
        }
        _error = _operation_error.load(std::memory_order_acquire);
        return _error == ERROR_SUCCESS;
    }

    bool failed() {
        _error = GetLastError();
        return false;
    }

  public:
    ~HttpRequest() {
        if (_request != nullptr) {
            WinHttpCloseHandle(_request);
            // Closing cancels pending I/O; its final callback releases the context.
            if (_callback) WaitForSingleObject(_closed, INFINITE);
        }
        if (_connection != nullptr) WinHttpCloseHandle(_connection);
        if (_session != nullptr) WinHttpCloseHandle(_session);
        if (_completed != nullptr) CloseHandle(_completed);
        if (_closed != nullptr) CloseHandle(_closed);
    }

    DWORD error() const { return _error; }

    bool post(const char* url, const char* data, size_t len, Output format, BufferWriter& response, DWORD& code) {
        if (_completed == nullptr || _closed == nullptr) return failed();
        std::wstring target = WindowsProfiler::wide(url);
        if (target.empty()) {
            _error = ERROR_NO_UNICODE_TRANSLATION;
            return false;
        }
        URL_COMPONENTS parts = {};
        parts.dwStructSize = sizeof(parts);
        parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = static_cast<DWORD>(-1);
        parts.dwUserNameLength = parts.dwPasswordLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(target.c_str(), 0, 0, &parts)) return failed();
        std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
        std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
        if (format == OUTPUT_OTLP && path.empty() && parts.dwExtraInfoLength == 0) {
            path = L"/v1development/profiles";
        }
        if (path.empty()) path = L"/";
        if (parts.dwExtraInfoLength != 0) {
            std::wstring extra(parts.lpszExtraInfo, parts.dwExtraInfoLength);
            path += extra.substr(0, extra.find(L'#'));
        }

        std::wstring proxy = httpEnv(parts.nScheme == INTERNET_SCHEME_HTTPS ? L"https_proxy" : L"http_proxy");
        if (proxy.empty()) proxy = httpEnv(L"all_proxy");
        if (httpBypass(host, httpEnv(L"no_proxy"))) proxy.clear();
        std::wstring proxyUser, proxyPassword;
        if (!proxy.empty()) {
            if (proxy.find(L"://") == std::wstring::npos) proxy.insert(0, L"http://");
            URL_COMPONENTS proxyParts = {};
            proxyParts.dwStructSize = sizeof(proxyParts);
            proxyParts.dwHostNameLength = proxyParts.dwUserNameLength =
                proxyParts.dwPasswordLength = static_cast<DWORD>(-1);
            if (!WinHttpCrackUrl(proxy.c_str(), 0, 0, &proxyParts)) return failed();
            if (proxyParts.nScheme != INTERNET_SCHEME_HTTP) {
                _error = ERROR_WINHTTP_UNRECOGNIZED_SCHEME;
                return false;
            }
            if (!httpCredential(proxyParts.lpszUserName, proxyParts.dwUserNameLength, proxyUser) ||
                    !httpCredential(proxyParts.lpszPassword, proxyParts.dwPasswordLength, proxyPassword)) return failed();
            proxy = std::wstring(proxyParts.lpszHostName, proxyParts.dwHostNameLength) +
                L":" + std::to_wstring(proxyParts.nPort);
        }

        _session = WinHttpOpen(nullptr, proxy.empty() ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                               proxy.empty() ? WINHTTP_NO_PROXY_NAME : proxy.c_str(),
                               WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
        if (_session == nullptr) return failed();
        if (!WinHttpSetTimeouts(_session, HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS)) return failed();
        _connection = WinHttpConnect(_session, host.c_str(), parts.nPort, 0);
        if (_connection == nullptr) return failed();
        _request = WinHttpOpenRequest(_connection, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
        if (_request == nullptr) return failed();
        DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES;
        if (!WinHttpSetOption(_request, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled))) return failed();
        DWORD autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        if (!WinHttpSetOption(_request, WINHTTP_OPTION_AUTOLOGON_POLICY, &autologon, sizeof(autologon))) return failed();
        if (parts.dwUserNameLength != 0) {
            std::wstring user, password;
            if (!httpCredential(parts.lpszUserName, parts.dwUserNameLength, user) ||
                    !httpCredential(parts.lpszPassword, parts.dwPasswordLength, password)) return failed();
            if (!WinHttpSetCredentials(_request, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_BASIC,
                                       user.c_str(), password.c_str(), nullptr)) return failed();
        }
        if (!proxyUser.empty() && !WinHttpSetCredentials(_request, WINHTTP_AUTH_TARGET_PROXY, WINHTTP_AUTH_SCHEME_BASIC,
                                                        proxyUser.c_str(), proxyPassword.c_str(), nullptr)) return failed();

        DWORD_PTR context = reinterpret_cast<DWORD_PTR>(this);
        if (!WinHttpSetOption(_request, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context))) return failed();
        if (WinHttpSetStatusCallback(_request, status, WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS |
                                     WINHTTP_CALLBACK_FLAG_HANDLES, 0) == WINHTTP_INVALID_STATUS_CALLBACK) return failed();
        _callback = true;
        const wchar_t* contentType = format == OUTPUT_OTLP ? L"application/x-protobuf" :
            format == OUTPUT_FLAMEGRAPH || format == OUTPUT_TREE ? L"text/html" : L"text/plain";
        std::wstring headers = std::wstring(L"Content-Type: ") + contentType +
            L"\r\nContent-Length: " + std::to_wstring(len) + L"\r\n";
        if (!finish(WinHttpSendRequest(_request, headers.c_str(), static_cast<DWORD>(headers.size()),
                                      WINHTTP_NO_REQUEST_DATA, 0,
                                      len > MAXDWORD ? WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH : static_cast<DWORD>(len),
                                      context))) return false;
        for (size_t offset = 0; offset < len;) {
            DWORD chunk = static_cast<DWORD>(std::min(len - offset, size_t(1024 * 1024)));
            if (!finish(WinHttpWriteData(_request, data + offset, chunk, nullptr))) return false;
            offset += chunk;
        }
        if (!finish(WinHttpReceiveResponse(_request, nullptr))) return false;
        DWORD size = sizeof(code);
        if (!WinHttpQueryHeaders(_request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &code, &size, WINHTTP_NO_HEADER_INDEX)) return failed();
        for (;;) {
            if (!finish(WinHttpReadData(_request, _buffer, sizeof(_buffer), nullptr))) return false;
            if (_read == 0) return true;
            if (_read > MAX_RESPONSE_SIZE - response.size()) {
                _error = ERROR_INSUFFICIENT_BUFFER;
                return false;
            }
            response.write(_buffer, _read);
        }
    }
};
}

Error HttpClient::send(const char* url, const char* data, size_t len, Output format) {
    HttpRequest request;
    BufferWriter response;
    DWORD status = 0;
    if (!request.post(url, data, len, format, response, status)) {
        Log::info("Failed to send profile to %s: WinHTTP error %lu", url, request.error());
        return Error(request.error() == ERROR_WINHTTP_TIMEOUT ? "HTTP request timed out" :
                     request.error() == ERROR_INSUFFICIENT_BUFFER ? "HTTP response exceeds 4 MB" : "HTTP request failed");
    }
    if (status < 200 || status >= 300) {
        response << '\0';
        Log::info("Failed to send profile to %s: HTTP %lu %s", url, status, response.buf());
        return Error("Remote endpoint rejected the profile");
    }
    Log::debug("Sent %llu bytes to %s", static_cast<unsigned long long>(len), url);
    return Error::OK;
}
