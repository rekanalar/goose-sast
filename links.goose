// The file checks: one tells the walk of the scanner whether a path is a
// symbolic link, and one gives the size of a regular file. The C of the
// package holds the two calls that the standard library has no name for.
namespace sast;

import os;

// The C call. It gives 1 for a link, 0 for anything else and -1 when
// it cannot tell.
extern "gs_sast_is_link" fn c_is_link(path: const u8[:]) -> i64;

// path_is_link reports whether the path is a symbolic link. A call
// that cannot tell counts as a link, so the walk never reads a path
// it doubts.
fn path_is_link(path: const u8[:]) -> bool {
    return c_is_link(path) != 0;
}

// The C call that gives the size of a regular file. It gives -1 for a
// directory, a pipe, a device and a path that does not exist.
extern "gs_sast_regular_size" fn c_regular_size(path: const u8[:]) -> i64;

// read_bounded reads a regular file of at most max bytes into the
// buffer. It gives false for a pipe, a device, a directory, a file that
// is too large and a file that cannot be read. The size bound holds
// before the read, so a file above it never reaches memory.
fn read_bounded(path: const u8[:], max: i64, out: u8[>..]&) -> bool {
    let size = c_regular_size(path);
    if size < 0 || size > max { return false; }
    return read_file(path, out);
}
