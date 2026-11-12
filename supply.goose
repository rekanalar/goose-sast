// The supply-chain checks: the pin of an import and the C part of a
// fetched package. Both read the cache of fetched packages on the disk.
// They read no network and write nothing.
namespace sast;

import os;

// put appends the text to the buffer.
fn sp_put(out: u8[>..]&, s: const u8[:]) {
    for b in s { out.push(b); }
}

// is_commit_ref reports whether the ref is 7 to 40 bytes of lowercase
// hexadecimal.
fn is_commit_ref(s: const u8[:]) -> bool {
    if s.len < 7 || s.len > 40 { return false; }
    for b in s {
        if !((b >= 48 && b <= 57) || (b >= 97 && b <= 102)) { return false; }
    }
    return true;
}

// seg_safe reports whether the text is one safe path segment: bytes of
// A-Z, a-z, 0-9, dot, dash and underscore, not empty, not . or ..
fn seg_safe(s: const u8[:]) -> bool {
    if s.len == 0 || s == "." || s == ".." { return false; }
    for b in s {
        let ok = (b >= 48 && b <= 57) || (b >= 65 && b <= 90)
              || (b >= 97 && b <= 122) || b == 46 || b == 45 || b == 95;
        if !ok { return false; }
    }
    return true;
}

// source_safe reports whether a source in the host form may build a
// cache path: at most 256 bytes, no leading slash, and every segment
// between slashes is safe.
fn source_safe(src: const u8[:]) -> bool {
    if src.len == 0 || src.len > 256 { return false; }
    var start: i64 = 0;
    var i: i64 = 0;
    while i <= src.len {
        if i == src.len || src[i] == 47 {
            if !seg_safe(src[start..i]) { return false; }
            start = i + 1;
        }
        i = i + 1;
    }
    return true;
}

// url_cache_name writes the cache directory name of a URL source: the
// last path segment without .git, a dash and the first 8 hex bytes of
// the FNV-1a 64 hash of the URL. It gives false when the name is unsafe.
fn url_cache_name(url: const u8[:], out: u8[>..]&) -> bool {
    var end = url.len;
    while end > 0 && url[end - 1] == 47 { end = end - 1; }
    var s = end;
    while s > 0 && url[s - 1] != 47 { s = s - 1; }
    var name = url[s..end];
    if ends_with(name, ".git") { name = name[0..name.len - 4]; }
    if !seg_safe(name) { return false; }
    sp_put(out, name);
    out.push(45);
    var h: u8[>..] = [];
    hex64(fnv64(url), h);
    for i in 0..8 { out.push(h[i]); }
    return true;
}

// cache_dir writes the cache directory of the package at the ref. It
// gives false when the root is empty or the source or the ref is not
// safe to build a path from.
fn cache_dir(root: const u8[:], src: const u8[:], ref: const u8[:],
             out: u8[>..]&) -> bool {
    if root.len == 0 || !seg_safe(ref) { return false; }
    var rel: u8[>..] = [];
    if find(src, "://") >= 0 {
        if !url_cache_name(src, rel) { return false; }
    } else {
        if !source_safe(src) { return false; }
        var slashes: i64 = 0;
        for b in src { if b == 47 { slashes = slashes + 1; } }
        // The form owner/repo is a GitHub source.
        if slashes == 1 { sp_put(rel, "github.com/"); }
        sp_put(rel, src);
    }
    sp_put(out, root);
    out.push(47);
    sp_put(out, rel[..]);
    out.push(47);
    sp_put(out, ref);
    return true;
}

// cache_root writes the cache root: GOOSE_HOME/pkg, or HOME/.goose/pkg,
// or USERPROFILE/.goose/pkg. It writes nothing when none is set.
fn cache_root(out: u8[>..]&) {
    var v: u8[>..] = [];
    if env("GOOSE_HOME", v) && v.len > 0 {
        sp_put(out, v[..]);
        sp_put(out, "/pkg");
        return;
    }
    var h: u8[>..] = [];
    if (env("HOME", h) || env("USERPROFILE", h)) && h.len > 0 {
        sp_put(out, h[..]);
        sp_put(out, "/.goose/pkg");
    }
}

// The bound of a file that the probe reads: 64 KiB.
const PROBE_FILE: i64 = 65536;

// ref_in reports whether the config text holds the refspec
// +refs/<kind>/<ref>: for the ref.
fn ref_in(text: const u8[:], kind: const u8[:], ref: const u8[:]) -> bool {
    var needle: u8[>..] = [];
    sp_put(needle, "+refs/");
    sp_put(needle, kind);
    needle.push(47);
    sp_put(needle, ref);
    needle.push(58);
    return find(text, needle[..]) >= 0;
}

// git_ref_kind reads the cached git config of the package and gives 2
// for a tag refspec, 3 for a branch refspec and 0 when it cannot tell.
fn git_ref_kind(dir: const u8[:], ref: const u8[:]) -> i64 {
    var path: u8[>..] = [];
    sp_put(path, dir);
    sp_put(path, "/.git/config");
    var text: u8[>..] = [];
    if path_is_link(path[..]) || !read_bounded(path[..], PROBE_FILE, text) { return 0; }
    if ref_in(text[..], "tags", ref) { return 2; }
    if ref_in(text[..], "heads", ref) { return 3; }
    return 0;
}

// pin_kind gives the kind of the pin of an import: 0 for a local path
// (no pin), 1 for a commit, 2 for a tag and 3 for a branch. The cache
// decides tag against branch. With no cache entry the form decides: a
// ref that starts with v and a digit is a tag.
fn pin_kind(tag: const u8[:], root: const u8[:], src: const u8[:]) -> i64 {
    if tag.len == 0 { return 0; }
    if is_commit_ref(tag) { return 1; }
    var dir: u8[>..] = [];
    if cache_dir(root, src, tag, dir) {
        let k = git_ref_kind(dir[..], tag);
        if k != 0 { return k; }
    }
    if tag.len >= 2 && tag[0] == 118 && tag[1] >= 48 && tag[1] <= 57 { return 2; }
    return 3;
}

// cpart_probe looks for a C part in the cache entry of the package. It
// gives 0 for none, 1 for a C part and 2 when it cannot check: no entry,
// an unsafe source, or a sidecar that is a link, too large or unreadable. It never follows a link.
fn cpart_probe(root: const u8[:], src: const u8[:], tag: const u8[:]) -> i64 {
    var dir: u8[>..] = [];
    if !cache_dir(root, src, tag, dir) { return 2; }
    if path_is_link(dir[..]) || !is_dir(dir[..]) { return 2; }
    var listing: u8[>..] = [];
    if !list_dir(dir[..], listing) { return 2; }
    var start: i64 = 0;
    var names: i64 = 0;
    var i: i64 = 0;
    while i < listing.len {
        if listing[i] == 10 {
            let name = listing[start..i];
            start = i + 1;
            names = names + 1;
            if names > 4096 { return 2; }
            let sidecar = ends_with(name, ".build");
            if sidecar || name == "CMakeLists.txt" {
                var path: u8[>..] = [];
                sp_put(path, dir[..]);
                path.push(47);
                sp_put(path, name);
                // A candidate that the probe cannot read whole is not "no C
                // part": a link, a file above the bound and a name that
                // the listing split all give 2.
                if path_is_link(path[..]) { return 2; }
                if !sidecar { return 1; }
                var text: u8[>..] = [];
                if !read_bounded(path[..], PROBE_FILE, text) { return 2; }
                if find(text[..], "c_sources") >= 0
                    || find(text[..], "cmake_target") >= 0 {
                    return 1;
                }
            }
        }
        i = i + 1;
    }
    return 0;
}

// check_supply runs the pin and the C part checks over the manifest of
// the last read, with the cache root of the run. The command calls it
// when a policy file is given.
fn check_supply(out: Finding[>..]&) -> i64 {
    var root: u8[>..] = [];
    cache_root(root);
    return check_pins(root[..], out) + check_cparts(root[..], out);
}

// check_pins reports each import with a branch pin, and each import
// with a tag pin when the policy asks for a commit pin.
fn check_pins(root: const u8[:], out: Finding[>..]&) -> i64 {
    let rule = reg_must(RULE_PIN);
    var found: i64 = 0;
    var i: i64 = 0;
    while i < dep_count() {
        let kind = pin_kind(dep_tag(i), root, dep_source(i));
        var why: const u8[:] = "";
        if kind == 3 {
            why = "the import names a branch; a branch can move";
        } else if kind == 2 && pol_pin_required {
            why = "the import names a tag; a tag can move, so pin a commit";
        }
        if why.len > 0 {
            var msg: u8[>..] = [];
            dep_msg(msg, dep_name(i), dep_tag(i), why);
            dep_report(out, rule, msg[..]);
            found = found + 1;
        }
        i = i + 1;
    }
    return found;
}

// check_cparts reports each fetched package with a C part, and each one
// that the check cannot read. It runs when the policy asks for it. A
// package on the allow list stays out.
fn check_cparts(root: const u8[:], out: Finding[>..]&) -> i64 {
    if !pol_cpart_report { return 0; }
    let rule = reg_must(RULE_CPART);
    var found: i64 = 0;
    var i: i64 = 0;
    while i < dep_count() {
        let tag = dep_tag(i);
        if tag.len > 0 && !pol_cpart_allowed(dep_source(i)) {
            let k = cpart_probe(root, dep_source(i), tag);
            var why: const u8[:] = "";
            if k == 1 { why = "the package builds C code on this machine"; }
            else if k == 2 { why = "the package cannot be checked for a C part"; }
            if why.len > 0 {
                var msg: u8[>..] = [];
                dep_msg(msg, dep_name(i), tag, why);
                dep_report(out, rule, msg[..]);
                found = found + 1;
            }
        }
        i = i + 1;
    }
    return found;
}
