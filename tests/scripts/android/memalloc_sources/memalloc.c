/*
 * SUSPICIOUS_MEMORY_ALLOC fixtures: one function per shape.
 *
 *   run_from_exec_mapping   maps PROT_EXEC memory, copies code into it and
 *                           calls into it - the loader shape (fires)
 *   flip_page_and_call      mprotect()s a buffer executable and calls it
 *                           through a function pointer (fires)
 *   heap_callback           malloc() plus a call through a caller-supplied
 *                           callback - ordinary C (does not fire)
 *   map_file_readonly       mmap() of a file, read-only, with branches but
 *                           no indirect transfer (does not fire)
 *   map_and_dispatch        mmap() plus a dense switch, which compiles to
 *                           a jump-table register branch (does not fire)
 *   map_rw_then_callback    a read-write anonymous mapping handed to a
 *                           callback: silent where the call-site layer reads
 *                           the protection (arm64, x86_64), fires where it
 *                           cannot (armeabi-v7a)
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*entry_fn)(int);

__attribute__((visibility("default"), noinline))
int run_from_exec_mapping(const uint8_t *code, size_t size, int arg) {
    void *page = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        return -1;
    }
    memcpy(page, code, size);
    return ((entry_fn)page)(arg);
}

__attribute__((visibility("default"), noinline))
int flip_page_and_call(uint8_t *buffer, size_t size, int arg) {
    uintptr_t start = (uintptr_t)buffer & ~(uintptr_t)4095;
    if (mprotect((void *)start, size + ((uintptr_t)buffer - start),
                 PROT_READ | PROT_EXEC) != 0) {
        return -1;
    }
    return ((entry_fn)buffer)(arg);
}

__attribute__((visibility("default"), noinline))
int heap_callback(size_t count, int (*visit)(int *, size_t)) {
    int *values = malloc(count * sizeof(int));
    if (values == NULL) {
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        values[i] = (int)i;
    }
    int result = visit(values, count);
    free(values);
    return result;
}

__attribute__((visibility("default"), noinline))
long map_file_readonly(int fd, size_t size) {
    const unsigned char *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        return -1;
    }
    long sum = 0;
    for (size_t i = 0; i < size; i++) {
        if (data[i] > 127) {
            sum += data[i];
        }
    }
    munmap((void *)data, size);
    return sum;
}

__attribute__((visibility("default"), noinline))
long map_and_dispatch(int fd, size_t size, int op) {
    const unsigned char *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        return -1;
    }
    long value;
    switch (op) {
    case 0: value = data[0]; break;
    case 1: value = data[1] * 3; break;
    case 2: value = data[2] ^ 0x55; break;
    case 3: value = data[3] + data[4]; break;
    case 4: value = data[5] << 2; break;
    case 5: value = data[6] - 9; break;
    case 6: value = data[7] | 0x80; break;
    case 7: value = data[8] * data[9]; break;
    default: value = 0; break;
    }
    munmap((void *)data, size);
    return value;
}

__attribute__((visibility("default"), noinline))
int map_rw_then_callback(size_t size, int (*fill)(void *, size_t)) {
    void *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED) {
        return -1;
    }
    int result = fill(buffer, size);
    munmap(buffer, size);
    return result;
}
