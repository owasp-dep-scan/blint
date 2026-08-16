/*
 * A deliberately vulnerable-shaped Windows kernel driver, built only to give
 * blint's IOCTL recovery something real to read.
 *
 * Every heuristic in blint/lib/driver_ioctl.py was written against disassembly
 * that a human wrote by hand. Hand-written assembly cannot tell you whether the
 * compiler actually emits the shapes the heuristics look for, and the LOLDrivers
 * corpus publishes import lists rather than binaries, so it cannot exercise them
 * either. This source closes that gap: it declares control codes whose values
 * are known ahead of time, dispatches them through the three shapes blint claims
 * to recover, and is compiled by the real MSVC toolchain so the recovered set
 * can be compared against ground truth.
 *
 * It deliberately exposes an unguarded MmMapIoSpace primitive through a device
 * object with no security descriptor, so the driver rules have something to fire
 * on. It is never loaded or run - loading it would be a genuine local privilege
 * escalation - and DriverEntry is only ever read, not executed.
 *
 * No WDK is required. The handful of kernel types used here are declared
 * locally, and the ntoskrnl imports are satisfied by an import library
 * generated from ntoskrnl.def.
 */

typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef void VOID;
typedef void *PVOID;
typedef long NTSTATUS;
/* Not wchar_t: that needs stddef.h in C mode, and Windows fixes it at 16 bits. */
typedef unsigned short WCHAR;
typedef unsigned __int64 ULONG64;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} UNICODE_STRING;

typedef union _LARGE_INTEGER {
    ULONG64 QuadPart;
} LARGE_INTEGER;

/*
 * The real DRIVER_OBJECT has a dozen fields before MajorFunction. Only the
 * offset matters here: the dispatch table sits at 0x70 on x64, which is what
 * blint's dispatch-slot detection keys on, so the leading fields are one pad.
 */
typedef struct _DRIVER_OBJECT {
    UCHAR Reserved[0x70];
    PVOID MajorFunction[28];
} DRIVER_OBJECT;

typedef struct _DEVICE_OBJECT DEVICE_OBJECT;
typedef struct _IRP IRP;

#define IRP_MJ_DEVICE_CONTROL 0x0E

#define FILE_DEVICE_TEST 0x8000
#define METHOD_BUFFERED 0
#define METHOD_NEITHER 3
#define FILE_ANY_ACCESS 0

#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

/*
 * Ground truth. The verifier hard-codes these same values, so a change in how
 * blint decodes CTL_CODE shows up as a mismatch rather than as agreement
 * between two copies of the same bug.
 *
 * Compare group: 0x80002400, 0x80002954, 0x80003444
 * Neither group: 0x800039F3  (raw user pointers, no ProbeForRead anywhere)
 * Switch group:  0x80002440 .. 0x8000247C, sixteen contiguous function codes
 * Table group:   0x80002480, 0x80002484, 0x80002488, 0x8000248C
 *
 * The compare group's function codes are deliberately far apart. Contiguous
 * ones let the compiler rewrite the if-chain as a jump table - clang does
 * exactly that - which would leave nothing testing the compare pass. Spread
 * this wide, a table would need thousands of entries, so compare instructions
 * are the only lowering available.
 */
#define IOCTL_COMPARE_A CTL_CODE(FILE_DEVICE_TEST, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_COMPARE_B CTL_CODE(FILE_DEVICE_TEST, 0xA55, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_COMPARE_C CTL_CODE(FILE_DEVICE_TEST, 0xD11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NEITHER CTL_CODE(FILE_DEVICE_TEST, 0xE7C, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SWITCH_BASE CTL_CODE(FILE_DEVICE_TEST, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TABLE_BASE CTL_CODE(FILE_DEVICE_TEST, 0x920, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SWITCH_CASE(n) CTL_CODE(FILE_DEVICE_TEST, 0x910 + (n), METHOD_BUFFERED, FILE_ANY_ACCESS)

__declspec(dllimport) NTSTATUS __stdcall IoCreateDevice(DRIVER_OBJECT *, ULONG, UNICODE_STRING *,
                                                        ULONG, ULONG, UCHAR, DEVICE_OBJECT **);
__declspec(dllimport) NTSTATUS __stdcall IoCreateSymbolicLink(UNICODE_STRING *, UNICODE_STRING *);
__declspec(dllimport) VOID __stdcall IoDeleteDevice(DEVICE_OBJECT *);
__declspec(dllimport) VOID __stdcall RtlInitUnicodeString(UNICODE_STRING *, const WCHAR *);
__declspec(dllimport) PVOID __stdcall MmMapIoSpace(LARGE_INTEGER, ULONG64, ULONG);
__declspec(dllimport) VOID __stdcall MmUnmapIoSpace(PVOID, ULONG64);

/*
 * The unguarded primitive. Physical memory is mapped at an address the caller
 * chose, with no privilege check anywhere in the image - the statically
 * decidable shape DRIVER_INSECURE_DEVICE_OBJECT describes.
 */
static ULONG ReadPhysical(ULONG64 address)
{
    LARGE_INTEGER physical;
    ULONG value = 0;
    PVOID mapped;

    physical.QuadPart = address;
    mapped = MmMapIoSpace(physical, sizeof(ULONG), 0);
    if (mapped) {
        value = *(volatile ULONG *)mapped;
        MmUnmapIoSpace(mapped, sizeof(ULONG));
    }
    return value;
}

/* Shape 1: a compare chain, which lowers to `cmp reg, imm32`. */
static ULONG DispatchCompareChain(ULONG code, ULONG64 argument)
{
    if (code == IOCTL_COMPARE_A) {
        return ReadPhysical(argument);
    }
    if (code == IOCTL_COMPARE_B) {
        return ReadPhysical(argument + 4);
    }
    if (code == IOCTL_COMPARE_C) {
        return ReadPhysical(argument + 8);
    }
    /*
     * METHOD_NEITHER: in a real driver this pointer comes straight from user
     * mode and would need ProbeForRead before the dereference. Nothing in this
     * image probes anything, which is the whole point.
     */
    if (code == IOCTL_NEITHER) {
        return *(volatile ULONG *)argument;
    }
    return 0;
}

/*
 * Shape 2: a dense switch over sixteen contiguous control codes. MSVC lowers
 * this to `sub reg, IOCTL_SWITCH_BASE` / `cmp reg, span` / `ja default` plus a
 * jump table, which names only the base as an immediate - the case blint's
 * switch recovery exists for.
 */
static ULONG DispatchSwitch(ULONG code, ULONG64 argument)
{
    switch (code) {
    case SWITCH_CASE(0):  return ReadPhysical(argument + 0x00);
    case SWITCH_CASE(1):  return ReadPhysical(argument + 0x10);
    case SWITCH_CASE(2):  return ReadPhysical(argument + 0x20);
    case SWITCH_CASE(3):  return ReadPhysical(argument + 0x30);
    case SWITCH_CASE(4):  return ReadPhysical(argument + 0x40);
    case SWITCH_CASE(5):  return ReadPhysical(argument + 0x50);
    case SWITCH_CASE(6):  return ReadPhysical(argument + 0x60);
    case SWITCH_CASE(7):  return ReadPhysical(argument + 0x70);
    case SWITCH_CASE(8):  return ReadPhysical(argument + 0x80);
    case SWITCH_CASE(9):  return ReadPhysical(argument + 0x90);
    case SWITCH_CASE(10): return ReadPhysical(argument + 0xA0);
    case SWITCH_CASE(11): return ReadPhysical(argument + 0xB0);
    case SWITCH_CASE(12): return ReadPhysical(argument + 0xC0);
    case SWITCH_CASE(13): return ReadPhysical(argument + 0xD0);
    case SWITCH_CASE(14): return ReadPhysical(argument + 0xE0);
    case SWITCH_CASE(15): return ReadPhysical(argument + 0xF0);
    default: return 0;
    }
}

/*
 * Shape 3: a dispatch table walked in a loop. The control codes only ever exist
 * as data, so no compare immediate names them and only the data-section scan
 * can recover them. `volatile` keeps the compiler from folding the table into a
 * compare chain and deleting it.
 */
static const volatile ULONG g_IoctlTable[] = {
    IOCTL_TABLE_BASE,
    IOCTL_TABLE_BASE + 4,
    IOCTL_TABLE_BASE + 8,
    IOCTL_TABLE_BASE + 12,
};

static ULONG DispatchTable(ULONG code, ULONG64 argument)
{
    ULONG index;

    for (index = 0; index < sizeof(g_IoctlTable) / sizeof(g_IoctlTable[0]); index++) {
        if (g_IoctlTable[index] == code) {
            return ReadPhysical(argument + index * 0x100);
        }
    }
    return 0;
}

static NTSTATUS __stdcall DispatchDeviceControl(DEVICE_OBJECT *device, IRP *irp)
{
    /*
     * A real dispatch routine reads the control code out of the IRP stack
     * location. That layout is not modelled here, so the code and argument are
     * taken from the two parameters instead; what matters for the test is the
     * dispatch shapes below, not how the values arrive.
     */
    ULONG code = (ULONG)(ULONG64)device;
    ULONG64 argument = (ULONG64)irp;

    return (NTSTATUS)(DispatchCompareChain(code, argument) + DispatchSwitch(code, argument) +
                      DispatchTable(code, argument));
}

NTSTATUS __stdcall DriverEntry(DRIVER_OBJECT *driver, UNICODE_STRING *registryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    DEVICE_OBJECT *device = 0;
    NTSTATUS status;

    (void)registryPath;

    /*
     * The names blint recovers from the UTF-16 strings in .rdata and reports as
     * device_names / symbolic_links.
     */
    RtlInitUnicodeString(&deviceName, L"\\Device\\BlintTestDriver");
    RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\BlintTestDriver");

    /* IoCreateDevice, not IoCreateDeviceSecure: no security descriptor. */
    status = IoCreateDevice(driver, 0, &deviceName, 0x8000, 0, 0, &device);
    if (status < 0) {
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (status < 0) {
        IoDeleteDevice(device);
        return status;
    }

    /* The store blint's dispatch-slot detection looks for: mov [rcx+0xe0], rax. */
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PVOID)DispatchDeviceControl;
    return 0;
}
