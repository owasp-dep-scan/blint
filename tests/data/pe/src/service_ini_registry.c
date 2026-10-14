/*
 * blint test fixture: a service that, on a custom control code, reads an INI
 * file and performs the registry write it describes - the CVE-2019-10617
 * shape (SERVICE_USER_WRITABLE_CONFIG). Built at test time with clang and
 * lld-link, parsed, never run.
 *
 * CONFIG_PATH selects where the INI lives; a bare file name next to the
 * binary is the negative variant. CONFIG_FROM_FOLDER builds the path from
 * SHGetFolderPathW(CSIDL_COMMON_APPDATA) instead of carrying it.
 */
typedef unsigned long DWORD;
typedef unsigned short WCHAR;
typedef int BOOL;

#ifndef CONFIG_PATH
#define CONFIG_PATH L"C:\\ProgramData\\Vendor\\VendorService.ini"
#endif

struct service_entry {
    const WCHAR *name;
    void *main;
};

__declspec(dllimport) BOOL __stdcall StartServiceCtrlDispatcherW(const struct service_entry *);
__declspec(dllimport) void *__stdcall RegisterServiceCtrlHandlerExW(const WCHAR *, void *, void *);
__declspec(dllimport) DWORD __stdcall GetPrivateProfileStringW(
    const WCHAR *, const WCHAR *, const WCHAR *, WCHAR *, DWORD, const WCHAR *);
__declspec(dllimport) long __stdcall RegCreateKeyExW(
    void *, const WCHAR *, DWORD, WCHAR *, DWORD, DWORD, void *, void **, DWORD *);
__declspec(dllimport) long __stdcall RegSetValueExW(
    void *, const WCHAR *, DWORD, DWORD, const void *, DWORD);

#ifdef CONFIG_FROM_FOLDER
__declspec(dllimport) long __stdcall SHGetFolderPathW(void *, int, void *, DWORD, WCHAR *);

static const WCHAR config_name[] = L"\\Vendor\\VendorService.ini";
static WCHAR config_path[260];

static const WCHAR *config_file(void)
{
    volatile int length = 0;
    int index = 0;
    SHGetFolderPathW(0, 0x23, 0, 0, config_path);
    while (config_path[length])
        length++;
    while (config_name[index] && length < 259)
        config_path[length++] = config_name[index++];
    config_path[length] = 0;
    return config_path;
}
#else
static const WCHAR config_path[] = CONFIG_PATH;

static const WCHAR *config_file(void)
{
    return config_path;
}
#endif
static WCHAR key_path[260];
static WCHAR value_name[260];
static WCHAR value_data[260];

static void apply_config(void)
{
    void *key = 0;
    DWORD count;
    const WCHAR *config = config_file();
    GetPrivateProfileStringW(L"Service", L"regPath", 0, key_path, 260, config);
    GetPrivateProfileStringW(L"Service", L"regValue", 0, value_name, 260, config);
    count = GetPrivateProfileStringW(L"Service", L"regData", 0, value_data, 260, config);
    if (RegCreateKeyExW((void *)0x80000002, key_path, 0, 0, 0, 0xF003F, 0, &key, 0) == 0)
        RegSetValueExW(key, value_name, 0, 1, value_data, count * 2);
}

static DWORD __stdcall control_handler(DWORD control, DWORD type, void *data, void *context)
{
    (void)type;
    (void)data;
    (void)context;
    if (control == 133)
        apply_config();
    return 0;
}

static void __stdcall service_main(DWORD argc, WCHAR **argv)
{
    (void)argc;
    (void)argv;
    RegisterServiceCtrlHandlerExW(L"VendorService", control_handler, 0);
    apply_config();
}

static const struct service_entry table[] = {{L"VendorService", service_main}, {0, 0}};

void start(void)
{
    StartServiceCtrlDispatcherW(table);
}
