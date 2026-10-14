/*
 * blint test fixture: register a device node under a chosen hardware ID and
 * ask Windows to install a driver for it (DEVICE_IDENTITY_SPOOFING). Built at
 * test time with clang and lld-link, parsed, never run.
 *
 * HARDWARE_ID selects the identity; a ROOT\ ID is the negative variant.
 */
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned short WCHAR;

#ifndef HARDWARE_ID
#define HARDWARE_ID L"USB\\VID_0489&PID_E078\0"
#endif

__declspec(dllimport) void *__stdcall SetupDiCreateDeviceInfoList(const void *, void *);
__declspec(dllimport) BOOL __stdcall SetupDiCreateDeviceInfoW(
    void *, const WCHAR *, const void *, const WCHAR *, void *, DWORD, void *);
__declspec(dllimport) BOOL __stdcall SetupDiSetDeviceRegistryPropertyW(
    void *, void *, DWORD, const void *, DWORD);
__declspec(dllimport) BOOL __stdcall SetupDiCallClassInstaller(DWORD, void *, void *);
__declspec(dllimport) DWORD __stdcall CM_Setup_DevNode(DWORD, DWORD);

static const WCHAR hardware_id[] = HARDWARE_ID;
static const char class_guid[16];
static char device_data[32];

void start(void)
{
    void *devices = SetupDiCreateDeviceInfoList(0, 0);
    if (!SetupDiCreateDeviceInfoW(devices, L"FixtureDevice", class_guid, 0, 0, 1, device_data))
        return;
    SetupDiSetDeviceRegistryPropertyW(devices, device_data, 1, hardware_id, sizeof(hardware_id));
    if (SetupDiCallClassInstaller(0x19, devices, device_data))
        CM_Setup_DevNode(0, 0);
}
