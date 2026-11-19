/* Minimal POSIX stand-in for <windows.h>, just what tools/iso-patch/engine/squashfs.c and
 * log.h use (file open/size/read and the types they need). It mocks the OS file API only;
 * no upstream code is replaced. */
#ifndef ASB_FUZZ_WINDOWS_SHIM_H
#define ASB_FUZZ_WINDOWS_SHIM_H
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

typedef void *HANDLE;
typedef uint32_t DWORD;
typedef int BOOL;
typedef union { struct { uint32_t LowPart; int32_t HighPart; } u; long long QuadPart; } LARGE_INTEGER;
typedef struct { uintptr_t Internal, InternalHigh; DWORD Offset, OffsetHigh; HANDLE hEvent; } OVERLAPPED;

#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define GENERIC_READ 0x80000000u
#define FILE_SHARE_READ 1u
#define FILE_SHARE_WRITE 2u
#define OPEN_EXISTING 3u
#define FILE_FLAG_SEQUENTIAL_SCAN 0x08000000u
#define FILE_ATTRIBUTE_NORMAL 0x80u
/* squashfs.c keeps its data-block xz decoder in a __declspec(thread) global. */
#define __declspec(a) ASB_DECLSPEC_##a
#define ASB_DECLSPEC_thread __thread

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

static inline HANDLE asb_fd_handle(int fd) { return (HANDLE)(intptr_t)(fd + 1); }
static inline int asb_handle_fd(HANDLE h) { return (int)(intptr_t)h - 1; }

static inline HANDLE CreateFileW(const wchar_t *path, DWORD access, DWORD share, void *sa,
                                 DWORD disposition, DWORD flags, HANDLE tmpl) {
    (void)access; (void)share; (void)sa; (void)disposition; (void)flags; (void)tmpl;
    char p[PATH_MAX];
    size_t n = wcstombs(p, path, sizeof p);
    if (n == (size_t)-1 || n >= sizeof p) return INVALID_HANDLE_VALUE;
    int fd = open(p, O_RDONLY);
    return fd < 0 ? INVALID_HANDLE_VALUE : asb_fd_handle(fd);
}
static inline BOOL GetFileSizeEx(HANDLE h, LARGE_INTEGER *sz) {
    struct stat st;
    if (fstat(asb_handle_fd(h), &st) != 0) return FALSE;
    sz->QuadPart = (long long)st.st_size;
    return TRUE;
}
static inline BOOL ReadFile(HANDLE h, void *buf, DWORD len, DWORD *got, OVERLAPPED *ov) {
    ssize_t r;
    if (ov) r = pread(asb_handle_fd(h), buf, len, (off_t)(((uint64_t)ov->OffsetHigh << 32) | ov->Offset));
    else r = read(asb_handle_fd(h), buf, len);
    if (r < 0) { if (got) *got = 0; return FALSE; }
    if (got) *got = (DWORD)r;
    return TRUE;
}
static inline BOOL CloseHandle(HANDLE h) { return close(asb_handle_fd(h)) == 0; }
static inline DWORD GetLastError(void) { return (DWORD)errno; }
#endif
