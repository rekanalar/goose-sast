// The C part of the goose-sast package.
//
// It holds two calls that the standard library has no name for. The
// first tells the walk of the scanner whether a path is a symbolic
// link. The walk skips a link, so a loop of links cannot make it read
// the same file again and a link cannot point the walk outside the tree
// it scans. The second gives the size of a regular file, and -1 for
// anything else, so the scanner reads no pipe, no device and no file
// above its size bound. Each call holds one argument, because a call
// with many argument slots crashes the TinyCC JIT on macOS/arm64.
//
// A reparse point of Windows counts as a link too. A junction and a
// OneDrive placeholder both carry the reparse attribute, and a walk
// that skips both cannot leave the tree.

#include "goose.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

#include <limits.h>
#include <string.h>

// The slice that an extern fn hands over. The layout is the one the
// generated C uses: a pointer and a count.
typedef struct { const uint8_t *data; int64_t len; } gs_sast_slice;

// gs_sast_is_link gives 1 when the path is a symbolic link or another
// reparse point, 0 when it is not, and -1 when the call cannot tell.
// A path that is too long counts as a link, so the walk never reads
// it.
int64_t gs_sast_is_link(gs_sast_slice path) {
    if (path.len <= 0 || path.len > 4096) { return path.len > 4096 ? 1 : 0; }
    char buf[4096];
    memcpy(buf, path.data, (size_t)path.len);
    buf[path.len] = 0;
#ifdef _WIN32
    // The wide call takes the path in UTF-16. A path that does not
    // convert counts as a link, so the walk never reads it.
    wchar_t wide[4096];
    int n = MultiByteToWideChar(CP_UTF8, 0, buf, -1, wide, 4096);
    if (n <= 0) { return 1; }
    DWORD attrs = GetFileAttributesW(wide);
    if (attrs == INVALID_FILE_ATTRIBUTES) { return -1; }
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;
#else
    struct stat st;
    if (lstat(buf, &st) != 0) { return -1; }
    return S_ISLNK(st.st_mode) ? 1 : 0;
#endif
}

// gs_sast_regular_size gives the size in bytes of a regular file. It
// gives -1 for a directory, a pipe, a device, a path that does not
// exist and a path that is too long. A link counts as the file it
// names, because a caller names its own config file and rule files.
int64_t gs_sast_regular_size(gs_sast_slice path) {
    if (path.len <= 0 || path.len > 4095) { return -1; }
    char buf[4096];
    memcpy(buf, path.data, (size_t)path.len);
    buf[path.len] = 0;
#ifdef _WIN32
    wchar_t wide[4096];
    int n = MultiByteToWideChar(CP_UTF8, 0, buf, -1, wide, 4096);
    if (n <= 0) { return -1; }
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExW(wide, GetFileExInfoStandard, &data)) { return -1; }
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { return -1; }
    return (int64_t)(((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow);
#else
    struct stat st;
    if (stat(buf, &st) != 0) { return -1; }
    if (!S_ISREG(st.st_mode)) { return -1; }
    return (int64_t)st.st_size;
#endif
}
