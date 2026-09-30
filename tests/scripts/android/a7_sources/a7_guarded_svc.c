/* Inline syscalls behind a conditional early return (armeabi-v7a).
 *
 * At -O2 the guard compiles to a conditional return (bxeq lr), so the svc
 * block after it is reached by fallthrough, not by a branch. Built with
 * -fomit-frame-pointer: in Thumb state r7 is otherwise the frame pointer. */

long a7_guarded_getpid(int enabled)
{
    if (!enabled)
        return 0;
    register long r7 __asm__("r7") = 20; /* __NR_getpid */
    register long r0 __asm__("r0");
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(r7) : "memory");
    return r0;
}

long a7_guarded_gettid(const int *flag)
{
    if (*flag == 0)
        return -1;
    register long r7 __asm__("r7") = 224; /* __NR_gettid */
    register long r0 __asm__("r0");
    __asm__ volatile("svc 0" : "=r"(r0) : "r"(r7) : "memory");
    return r0;
}
