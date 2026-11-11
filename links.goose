// The link check: it tells the walk of the scanner whether a path is a
// symbolic link. The C of the package holds the one call that the
// standard library has no name for.
namespace sast;

// The C call. It gives 1 for a link, 0 for anything else and -1 when
// it cannot tell.
extern "gs_sast_is_link" fn c_is_link(path: const u8[:]) -> i64;

// path_is_link reports whether the path is a symbolic link. A call
// that cannot tell counts as a link, so the walk never reads a path
// it doubts.
fn path_is_link(path: const u8[:]) -> bool {
    return c_is_link(path) != 0;
}
