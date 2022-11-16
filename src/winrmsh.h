#pragma once
#include <Windows.h>
#define WSMAN_API_VERSION_1_0
#include <wsman.h>
#include <cstdio>
#include <vector>
#include "detours.h"

#define BOF_IMPORT(ret, call, dll, name, ...)\
    extern "C" __declspec(dllimport) ret call dll##$##name(__VA_ARGS__);

BOF_IMPORT(long long, __cdecl, msvcrt, atoll, const char*)
BOF_IMPORT(long long, __cdecl, msvcrt, _wtoi, const wchar_t*);
BOF_IMPORT(int, __cdecl, msvcrt, wcscmp, wchar_t const*,wchar_t const*);
BOF_IMPORT(int, __cdecl, msvcrt, _stricmp, char const*,char const*);
BOF_IMPORT(int, __cdecl, msvcrt, _snprintf, char*,size_t,char const*,...);
BOF_IMPORT(void, __cdecl, msvcrt, memcpy, void* ,const void*,size_t);
BOF_IMPORT(void, __cdecl, msvcrt, memset, void*,int,size_t);
BOF_IMPORT(void*, __cdecl, msvcrt, malloc, size_t);
BOF_IMPORT(void, __cdecl, msvcrt, free, void*);
BOF_IMPORT(BOOL, __stdcall, kernel32, SetEvent, HANDLE);
BOF_IMPORT(HANDLE, __stdcall, kernel32, CreateEventA, void*,BOOL,BOOL,void*);
BOF_IMPORT(DWORD, __stdcall, kernel32, WaitForSingleObject, HANDLE,DWORD);
BOF_IMPORT(BOOL, __stdcall, kernel32, CloseHandle, HANDLE);
BOF_IMPORT(HMODULE, __stdcall, kernel32, LoadLibraryW, const wchar_t*);
BOF_IMPORT(DWORD, __stdcall, kernel32, GetLastError);
BOF_IMPORT(BOOL, __stdcall, kernel32, VirtualProtect, void*,size_t,DWORD,DWORD*);
BOF_IMPORT(int, __stdcall, kernel32, MultiByteToWideChar, UINT, DWORD, LPCCH, int, LPWSTR, int);
BOF_IMPORT(int, WINAPI, kernel32, WideCharToMultiByte, UINT,DWORD,LPCWCH,int,LPSTR,int,LPCCH,LPBOOL);
BOF_IMPORT(HLOCAL, __stdcall, kernel32, LocalFree, HLOCAL);
BOF_IMPORT(wchar_t**, __stdcall, shell32, CommandLineToArgvW, LPCWSTR,int*);
BOF_IMPORT(DWORD, WINAPI, wsmsvc, WSManInitialize, DWORD,WSMAN_API_HANDLE*);
BOF_IMPORT(DWORD, WINAPI, wsmsvc, WSManCreateSession,
    _In_ WSMAN_API_HANDLE apiHandle,
    _In_opt_ PCWSTR connection,
    DWORD flags,
    _In_opt_ WSMAN_AUTHENTICATION_CREDENTIALS *serverAuthenticationCredentials,
    _In_opt_ WSMAN_PROXY_INFO *proxyInfo,
    _Out_ WSMAN_SESSION_HANDLE *session
);
BOF_IMPORT(DWORD, WINAPI, wsmsvc, WSManCreateShell,
    WSMAN_SESSION_HANDLE,
    DWORD,
    PCWSTR,WSMAN_SHELL_STARTUP_INFO*,
    WSMAN_OPTION_SET * options,
    _In_opt_ WSMAN_DATA * createXml,
    _In_ WSMAN_SHELL_ASYNC * async,
    _Out_ WSMAN_SHELL_HANDLE * shell
);
BOF_IMPORT(DWORD, WINAPI, wsmsvc, WSManRunShellCommand,
    _Inout_ WSMAN_SHELL_HANDLE shell,
    DWORD,PCWSTR,WSMAN_COMMAND_ARG_SET,WSMAN_OPTION_SET*,
    WSMAN_SHELL_ASYNC*,
    WSMAN_COMMAND_HANDLE*
);
BOF_IMPORT(DWORD, WINAPI, wsmsvc, WSManCloseSession,
    WSMAN_SESSION_HANDLE,DWORD
);
BOF_IMPORT(DWORD, WINAPI, wsmsvc, WSManDeinitialize,
    WSMAN_API_HANDLE,DWORD
);
BOF_IMPORT(void, WINAPI, wsmsvc, WSManReceiveShellOutput,
    WSMAN_SHELL_HANDLE, WSMAN_COMMAND_HANDLE,
    DWORD,WSMAN_STREAM_ID_SET,WSMAN_SHELL_ASYNC,WSMAN_OPERATION_HANDLE *);

BOF_IMPORT(DWORD, WINAPI, wsmsvc, WSManCloseOperation,
    WSMAN_OPERATION_HANDLE,DWORD);
BOF_IMPORT(void, WINAPI, wsmsvc, WSManSendShellInput,
    WSMAN_SHELL_HANDLE,
    WSMAN_COMMAND_HANDLE,
    DWORD,PCWSTR,WSMAN_DATA*,
    BOOL,
    WSMAN_SHELL_ASYNC *,
    WSMAN_OPERATION_HANDLE *
);
BOF_IMPORT(void, WINAPI, wsmsvc, WSManCloseCommand,WSMAN_COMMAND_HANDLE,DWORD,WSMAN_SHELL_ASYNC *);
BOF_IMPORT(void, WINAPI, wsmsvc, WSManCloseShell,WSMAN_SHELL_HANDLE,DWORD,WSMAN_SHELL_ASYNC*);

struct WinRMContext
{
    WSMAN_API_HANDLE api;
    WSMAN_SESSION_HANDLE session;
    WSMAN_SHELL_HANDLE shell;
    WSMAN_COMMAND_HANDLE command;
    WSMAN_OPERATION_HANDLE operation;
    HANDLE events[2];
    WSMAN_SHELL_ASYNC async[2];
    DWORD errors[2];
};

struct OutputBuffer
{
    char* data;
    int length;
    int capacity;
};

struct GlobalData {
    const wchar_t* shell;
    const wchar_t* username;
    const wchar_t* password;
    const wchar_t* url;
    const wchar_t* cmdline;
    OutputBuffer output;
    WinRMContext* ctx;
    decltype(RegQueryValueExW)* Real_RegQueryValueExW;
};

#ifdef BUILD_BOF

extern "C" {
#include "beacon.h"
}

#define errorf(...) BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__)
#define printf(...) BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)
#define wcscmp(...) msvcrt$wcscmp(__VA_ARGS__)
#define _stricmp(...) msvcrt$_stricmp(__VA_ARGS__)
#define snprintf(...) msvcrt$_snprintf(__VA_ARGS__)
#define atoll(...) msvcrt$atoll(__VA_ARGS__)
#define _wtoi(...) msvcrt$_wtoi(__VA_ARGS__)
#define malloc(...) msvcrt$malloc(__VA_ARGS__)
#define memcpy(...) msvcrt$memcpy(__VA_ARGS__)
#define memset(...) msvcrt$memset(__VA_ARGS__)
#define free(...) msvcrt$free(__VA_ARGS__)
#define SetEvent(...) kernel32$SetEvent(__VA_ARGS__)
#define CreateEventA(...) kernel32$CreateEventA(__VA_ARGS__)
#define WaitForSingleObject(...) kernel32$WaitForSingleObject(__VA_ARGS__)
#define CloseHandle(...) kernel32$CloseHandle(__VA_ARGS__)
#define LoadLibraryW(...) kernel32$LoadLibraryW(__VA_ARGS__)
#define GetLastError(...) kernel32$GetLastError(__VA_ARGS__)
#define VirtualProtect(...) kernel32$VirtualProtect(__VA_ARGS__)
#define AddAtomA(...) kernel32$AddAtomA(__VA_ARGS__)
#define GetAtomNameA(...) kernel32$GetAtomNameA(__VA_ARGS__)
#define MultiByteToWideChar(...) kernel32$MultiByteToWideChar(__VA_ARGS__)
#define WideCharToMultiByte(...) kernel32$WideCharToMultiByte(__VA_ARGS__)
#define CommandLineToArgvW(...) shell32$CommandLineToArgvW(__VA_ARGS__)
#define LocalFree(...) kernel32$LocalFree(__VA_ARGS__)
#define WSManInitialize(...) wsmsvc$WSManInitialize(__VA_ARGS__)
#define WSManCreateSession(...) wsmsvc$WSManCreateSession(__VA_ARGS__)
#define WSManCreateShell(...) wsmsvc$WSManCreateShell(__VA_ARGS__)
#define WSManRunShellCommand(...) wsmsvc$WSManRunShellCommand(__VA_ARGS__)
#define WSManCloseSession(...) wsmsvc$WSManCloseSession(__VA_ARGS__)
#define WSManDeinitialize(...) wsmsvc$WSManDeinitialize(__VA_ARGS__)
#define WSManCloseOperation(...) wsmsvc$WSManCloseOperation(__VA_ARGS__)
#define WSManSendShellInput(...) wsmsvc$WSManSendShellInput(__VA_ARGS__)

#else

void dprintf(const char* format, ...);
#define printf(...) dprintf(__VA_ARGS__)
#define errorf(...) dprintf(__VA_ARGS__)

#endif
