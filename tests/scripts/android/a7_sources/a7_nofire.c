/*
 * A7 K1 — the no-fire side: the benign shapes the reviewer measured as the
 * false-positive population of every single-signal form.
 *
 * Each function here carries one signal alone, in the exact shape the
 * benign carriers carry it, and must stay silent under the K2 rules:
 *
 *   a7_unwinder          an unwinder/crash reporter reading /proc/self/maps;
 *   a7_crash_handler     ptrace on a *child* (PTRACE_ATTACH / SEIZE /
 *                         CONT / DETACH), never PTRACE_TRACEME;
 *   a7_sdk_probe         a plain ro.build.version.sdk read;
 *   a7_shell_exec        execve of /system/bin/sh;
 *   a7_soname_dlopen     dlopen of a bare SONAME.
 *
 * The gates that keep these silent are the point of the fixture: the rules
 * key on call-site constants (request codes, paths, property names), not on
 * imports or strings.
 */

#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int a7_nofire_sink;

/* The unwinder shape: fopen /proc/self/maps and walk it (libjnidispatch,
 * libsentry, libmozglue, libvlc, libart, libc itself). */
long a7_unwinder(unsigned long pc)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL)
    {
        return -1;
    }
    char line[512];
    long base = -1;
    while (fgets(line, sizeof(line), maps) != NULL)
    {
        unsigned long start = 0;
        unsigned long end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2 && pc >= start && pc < end)
        {
            base = (long)start;
            break;
        }
    }
    fclose(maps);
    return base;
}

/* The crash-handler shape (libsentry, libunwindstack, libmemunreachable,
 * libc_malloc_debug, libfdtrack): a parent debugging a child it forked. */
int a7_crash_handler(void)
{
    pid_t child = fork();
    if (child == 0)
    {
        /* The child stops itself so the parent never needs TRACEME. */
        raise(SIGSTOP);
        _exit(0);
    }
    if (child < 0)
    {
        return -1;
    }
    int status = 0;
    waitpid(child, &status, 0);
    long rc = ptrace(PTRACE_ATTACH, child, 0, 0);
    if (rc == 0)
    {
        ptrace(PTRACE_CONT, child, 0, 0);
        waitpid(child, &status, 0);
        ptrace(PTRACE_DETACH, child, 0, 0);
    }
    else
    {
        ptrace(PTRACE_SEIZE, child, 0, 0);
        ptrace(PTRACE_INTERRUPT, child, 0, 0);
        waitpid(child, &status, 0);
        ptrace(PTRACE_DETACH, child, 0, 0);
    }
    waitpid(child, &status, 0);
    return (int)rc;
}

/* The benign property read: SDK level gating (ubiquitous, 475 tier-0
 * libraries import __system_property_*). */
int a7_sdk_probe(void)
{
    char value[PROP_VALUE_MAX] = {0};
    int len = __system_property_get("ro.build.version.sdk", value);
    if (len > 0)
    {
        return atoi(value);
    }
    return 0;
}

/* The shell shape: execve of /system/bin/sh, the standard system() path —
 * not su (libdumpstateutil is the su counterpart in tier 0). */
int a7_shell_exec(const char *script)
{
    pid_t pid = fork();
    if (pid == 0)
    {
        char *const argv[] = {(char *)"/system/bin/sh", (char *)"-c", (char *)script, NULL};
        char *const envp[] = {NULL};
        execve("/system/bin/sh", argv, envp);
        _exit(127);
    }
    int status = 0;
    if (pid > 0)
    {
        waitpid(pid, &status, 0);
    }
    return status;
}

/* The loader shape: dlopen of a bare SONAME resolved by the dynamic
 * linker against the app's library path (82 tier-0, 20 app libraries). */
int a7_soname_dlopen(void)
{
    void *handle = dlopen("libc++_shared.so", RTLD_NOW);
    if (handle == NULL)
    {
        handle = dlopen("liblog.so", RTLD_NOW);
    }
    if (handle != NULL)
    {
        a7_nofire_sink = 1;
        dlclose(handle);
    }
    return handle != NULL;
}

int a7_nofire_run(const char *script)
{
    int total = 0;
    total += (int)a7_unwinder(0);
    total += a7_crash_handler();
    total += a7_sdk_probe();
    total += a7_shell_exec(script);
    total += a7_soname_dlopen();
    return total + a7_nofire_sink;
}
