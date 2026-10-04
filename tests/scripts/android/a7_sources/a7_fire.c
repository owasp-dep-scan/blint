/*
 * The fire side of the six native capability families.
 *
 * Every shape here is the precise form the native rules target: a call-site
 * constant the abstract interpreter can recover (a request code, a path, a
 * property name) or an inline syscall instruction. One exported function
 * per family so a fixture failure names its family directly; the exported
 * names also keep lld from dead-stripping the shapes at -O2.
 *
 * No-fire twins live in a7_nofire.c: the measured benign shapes (an
 * unwinder, a crash handler's PTRACE_ATTACH, an SDK-version read, a shell
 * execve, a bare-SONAME dlopen).
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__) || defined(__arm__)
#define A7_HAVE_SVC 1
#endif

/* Family 2's path list, RootBeer-shaped (scottyab/rootbeer Const.suPaths
 * at 0.1.2 carries the same directories from Java; here they are native
 * constants, which is the form the call-site rule reads). */
static const char *const a7_su_paths[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/system/sd/xbin/su",
    "/vendor/bin/su",
};
static const size_t a7_su_path_count = sizeof(a7_su_paths) / sizeof(a7_su_paths[0]);

static int a7_sink;

/* Family 1: anti-debug — ptrace(PTRACE_TRACEME), the request constant 0. */
int a7_anti_debug(void)
{
    long rc = ptrace(PTRACE_TRACEME, 0, 0, 0);
    return (int)rc;
}

/* Family 2: root check — constant su paths reaching access() and stat(). */
int a7_root_check(void)
{
    int found = 0;
    for (size_t i = 0; i < a7_su_path_count; i++)
    {
        if (access(a7_su_paths[i], F_OK) == 0)
        {
            found = 1;
        }
        struct stat st;
        if (stat(a7_su_paths[i], &st) == 0)
        {
            found = 1;
        }
        if (fopen(a7_su_paths[i], "r") != NULL)
        {
            found = 1;
        }
    }
    return found;
}

/* Family 3: su execution — execl/system/popen with a constant su path. */
int a7_su_exec(const char *cmd)
{
    int status = 0;
    pid_t pid = fork();
    if (pid == 0)
    {
        execl("/system/bin/su", "su", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    if (pid > 0)
    {
        waitpid(pid, &status, 0);
    }
    if (system("/system/bin/su -c id") != 0)
    {
        a7_sink = 1;
    }
    FILE *pipe = popen("/system/xbin/su -c id", "r");
    if (pipe != NULL)
    {
        char line[128];
        if (fgets(line, sizeof(line), pipe) != NULL)
        {
            a7_sink = line[0];
        }
        pclose(pipe);
    }
    return status;
}

/* Family 4: emulator fingerprint — __system_property_get with constant
 * emulator property names, plus the goldfish/ranchu hardware comparison. */
int a7_emulator_fingerprint(void)
{
    char value[PROP_VALUE_MAX] = {0};
    int score = 0;
    if (__system_property_get("ro.kernel.qemu", value) > 0 && value[0] == '1')
    {
        score = 1;
    }
    if (__system_property_get("ro.hardware", value) > 0)
    {
        if (strcmp(value, "goldfish") == 0 || strcmp(value, "ranchu") == 0)
        {
            score = 1;
        }
    }
    if (__system_property_get("ro.product.model", value) > 0 && strcmp(value, "sdk") == 0)
    {
        score = 1;
    }
    return score;
}

/* Family 5: loading code from a writable location — dlopen and
 * android_dlopen_ext with constant paths under /data, /sdcard, /storage. */
int a7_writable_dlopen(void)
{
    void *handle = dlopen("/data/local/tmp/plugin.so", RTLD_NOW);
    if (handle != NULL)
    {
        dlclose(handle);
    }
    handle = dlopen("/sdcard/Android/data/plugin.so", RTLD_NOW);
    if (handle != NULL)
    {
        dlclose(handle);
    }
    handle = dlopen("/data/data/com.example/files/libextra.so", RTLD_NOW);
    if (handle != NULL)
    {
        dlclose(handle);
    }
    return handle != NULL;
}

/* Family 6: inline syscalls — the raw instruction, per ABI.
 *
 * arm64: svc #0 with the syscall number in x8 (write(1, msg, len));
 * arm32: svc 0 with the number in r7;
 * x86_64: syscall (rax) and the legacy int 0x80 form. */
#if defined(A7_HAVE_SVC) && defined(__aarch64__)
static const char a7_msg[] = "a7";
int a7_inline_syscall(void)
{
    register long x0 __asm__("x0") = 1;
    register long x1 __asm__("x1") = (long)a7_msg;
    register long x2 __asm__("x2") = (long)(sizeof(a7_msg) - 1);
    register long x8 __asm__("x8") = 64; /* __NR_write */
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8)
                     : "memory");
    return (int)x0;
}
#elif defined(A7_HAVE_SVC) && defined(__arm__)
static const char a7_msg[] = "a7";
int a7_inline_syscall(void)
{
    register long r0 __asm__("r0") = 1;
    register long r1 __asm__("r1") = (long)a7_msg;
    register long r2 __asm__("r2") = (long)(sizeof(a7_msg) - 1);
    register long r7 __asm__("r7") = 4; /* __NR_write */
    __asm__ volatile("svc 0"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), "r"(r7)
                     : "memory");
    return (int)r0;
}
#elif defined(__x86_64__)
static const char a7_msg[] = "a7";
int a7_inline_syscall(void)
{
    const void *msg = a7_msg;
    long rc = 0;
    __asm__ volatile(
        "mov $1, %%rax\n\t"
        "mov $1, %%rdi\n\t"
        "mov $2, %%rdx\n\t"
        "mov %1, %%rsi\n\t"
        "syscall"
        : "=a"(rc)
        : "r"(msg)
        : "rdi", "rsi", "rdx", "memory");
    long rc2 = 0;
    __asm__ volatile(
        "mov $4, %%eax\n\t"
        "mov $1, %%ebx\n\t"
        "mov $2, %%edx\n\t"
        "mov %1, %%rcx\n\t"
        "int $0x80"
        : "=a"(rc2)
        : "r"(msg)
        : "ebx", "ecx", "edx", "memory");
    return (int)(rc + rc2);
}
#else
int a7_inline_syscall(void)
{
    return write(1, "a7", 2);
}
#endif

/* A driver that references every family so a whole-library sweep of the
 * disassembler always reaches them even if a future toolchain changes its
 * dead-code decisions. */
int a7_run_all(const char *cmd)
{
    int total = 0;
    total += a7_anti_debug();
    total += a7_root_check();
    total += a7_su_exec(cmd);
    total += a7_emulator_fingerprint();
    total += a7_writable_dlopen();
    total += a7_inline_syscall();
    return total + a7_sink;
}
