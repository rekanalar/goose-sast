// The helpers and the globals that the tests share.
namespace common;

import std;
import os;
import json;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

var fails: i64 = 0;
var site_src: const u8[:][>..] = [];
var site_id: const u8[:][>..] = [];
var site_kind: i64[>..] = [];

fn check(ok: bool, what: const u8[:]) {
    if !ok {
        fails = fails + 1;
        print("FAIL ", what);
    }
}

// count_rule gives how many findings of the rule ID the text yields.
// The helper uses the strict profile, so every rule of the package
// runs. The default profile leaves three rules out.
fn count_rule(src: const u8[:], id: const u8[:]) -> i64 {
    var o = sast::default_options();
    o.profile = sast::PROFILE_STRICT;
    return count_rule_with(src, id, o);
}

// count_rule_profile gives how many findings of the rule ID the text
// yields under the given profile.
fn count_rule_profile(src: const u8[:], id: const u8[:], profile: i64) -> i64 {
    var o = sast::default_options();
    o.profile = profile;
    return count_rule_with(src, id, o);
}

fn count_rule_with(src: const u8[:], id: const u8[:], o: sast::Options) -> i64 {
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", src, o, fs);
    let want = sast::reg_find(id);
    var n: i64 = 0;
    for f in fs { if f.rule == want { n = n + 1; } }
    return n;
}

// scan_tree scans the tree at the path under the given profile. It
// gives the count of the scanned files.
fn scan_tree(path: const u8[:], profile: i64) -> i64 {
    var o = sast::default_options();
    o.profile = profile;
    var fs: sast::Finding[>..] = [];
    sast::scan_reset();
    var budget = o.max_files;
    let scanned, skipped = sast::scan_dir_budget(path, o, fs, budget);
    return scanned;
}

// The shape tests build each value from pieces at run time, so that no
// file of the package holds a whole shape.
fn put(b: u8[>..]&, s: const u8[:]) { for c in s { b.push(c); } }

fn fill(b: u8[>..]&, c: u8, n: i64) {
    var i: i64 = 0;
    while i < n { b.push(c); i = i + 1; }
}

// s_count gives the findings of the rule ID under the default profile.
fn s_count(src: const u8[:], id: const u8[:]) -> i64 {
    return count_rule_profile(src, id, sast::PROFILE_DEFAULT);
}

// chk builds lead, a, b, n bytes of c and tail. It checks the count of
// the rule ID.
fn chk(lead: const u8[:], a: const u8[:], b: const u8[:], c: u8, n: i64,
       tail: const u8[:], id: const u8[:], want: i64, what: const u8[:]) {
    var buf: u8[>..] = [];
    put(buf, lead); put(buf, a); put(buf, b);
    fill(buf, c, n);
    put(buf, tail);
    check(s_count(buf[..], id) == want, what);
}

// holds reports whether the text holds the needle.
fn holds(hay: const u8[:], needle: const u8[:]) -> bool {
    return find(hay, needle) >= 0;
}

// shape_id gives the ID of the shape rule at the place i.
fn shape_id(i: i64) -> const u8[:] {
    if i == 0 { return "S101"; }
    if i == 1 { return "S102"; }
    if i == 2 { return "S103"; }
    return "S104";
}

// key_type gives the type word of a private key header and a space.
fn key_type(i: i64) -> const u8[:] {
    if i == 0 { return ""; }
    if i == 1 { return "RSA "; }
    if i == 2 { return "EC "; }
    if i == 3 { return "DSA "; }
    if i == 4 { return "OPENSSH "; }
    if i == 5 { return "PGP "; }
    return "ENCRYPTED ";
}

// no_secret checks that an output holds no secret and no run of its body.
fn no_secret(out: const u8[:], a: const u8[:], b: const u8[:], c: const u8[:]) {
    check(!holds(out, a) && !holds(out, b) && !holds(out, c), "no output holds a secret");
    check(!holds(out, "22222222") && !holds(out, "aaaaaaaa") && !holds(out, "bbbbbbbb"), "no output holds a body");
}

// self_scan gives the count of the shape findings in a file of the package.
fn self_scan(path: const u8[:]) -> i64 {
    var text: u8[>..] = [];
    read_file(path, text);
    var n: i64 = 0;
    var i: i64 = 0;
    while i < 4 { n = n + s_count(text[..], shape_id(i)); i = i + 1; }
    return n;
}

// count_words gives the words of the text. A space ends a word.
fn count_words(t: const u8[:]) -> i64 {
    var n: i64 = 0;
    var inside = false;
    for c in t {
        if c == 32 || c == 10 { inside = false; }
        else if !inside { inside = true; n = n + 1; }
    }
    return n;
}

// longest_sentence gives the most words in one sentence. A full stop
// ends a sentence. The count of the sentences goes to the second value.
fn longest_sentence(t: const u8[:]) -> i64, i64 {
    var most: i64 = 0;
    var sentences: i64 = 0;
    var start: i64 = 0;
    var i: i64 = 0;
    while i < t.len {
        if t[i] == 46 {
            let w = count_words(t[start..i]);
            if w > most { most = w; }
            sentences = sentences + 1;
            start = i + 1;
        }
        i = i + 1;
    }
    return most, sentences;
}

// shape_free reports whether the text holds none of the four shapes.
// The scan runs once and the four rules share it.
fn shape_free(text: const u8[:]) -> bool {
    var o = sast::default_options();
    o.profile = sast::PROFILE_ALL;
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", text, o, fs);
    for f in fs {
        if f.rule == sast::reg_find("S101") || f.rule == sast::reg_find("S102")
            || f.rule == sast::reg_find("S103") || f.rule == sast::reg_find("S104") {
            return false;
        }
    }
    return true;
}

// scan_profile gives the findings of the text under the profile.
fn scan_profile(src: const u8[:], profile: i64, fs: sast::Finding[>..]&) {
    var o = sast::default_options();
    o.profile = profile;
    sast::findings_reset();
    sast::scan_text("src/a.goose", src, o, fs);
}

// field_table checks the key names of a JSON object. The table lists
// the keys with a bar before and after each. Every key must be in the
// table, and the table must hold no key that the object lacks.
fn field_table(node: json::Node?, table: const u8[:], what: const u8[:]) {
    if !node { check(false, what); return; }
    var seen: i64 = 0;
    var unknown: i64 = 0;
    json::each(node) { child =>
        var pat: u8[>..] = [];
        pat.push(124); put(pat, child.key); pat.push(124);
        if find(table, pat[..]) < 0 { unknown = unknown + 1; }
        seen = seen + 1;
    };
    var listed: i64 = 0;
    for c in table { if c == 124 { listed = listed + 1; } }
    check(unknown == 0 && seen == listed - 1, what);
}

// shape_time gives the milliseconds that nl_build and rule_shapes take
// on the buffer, and the count of the findings.
fn shape_time(buf: const u8[:]) -> i64, i64 {
    var out: sast::Finding[>..] = [];
    let t0 = clock_ns();
    let n = sast::rule_shapes(buf, 0, out);
    return (clock_ns() - t0) / 1000000, n;
}

// take_fp copies the fingerprint of a JSON finding into out.
fn take_fp(node: json::Node&, out: u8[>..]&) {
    let v, ok = json::as_string(json::member(node, "fingerprint"));
    if ok { put(out, v); }
}

// take_sfp copies the fingerprint of a SARIF result into out.
fn take_sfp(node: json::Node&, out: u8[>..]&) {
    let pf = json::member(node, "partialFingerprints");
    if pf {
        let v, ok = json::as_string(json::member(pf, "goose-sast/finding"));
        if ok { put(out, v); }
    }
}

// mk_dirs makes each directory level of the path.
fn mk_dirs(path: const u8[:]) {
    var i: i64 = 1;
    while i <= path.len {
        if i == path.len || path[i] == 47 { make_dir(path[0..i]); }
        i = i + 1;
    }
}

// mk_file writes a file in a cache entry, after its directories.
fn mk_file(dir: const u8[:], name: const u8[:], text: const u8[:]) {
    mk_dirs(dir);
    var p: u8[>..] = [];
    put(p, dir); put(p, "/"); put(p, name);
    write_file(p[..], text);
}

// supply_pol loads a policy text and checks that it parses.
fn supply_pol(text: const u8[:], what: const u8[:]) {
    var e: u8[>..] = [];
    check(sast::read_policy(text, e), what);
}

// supply_count runs the pin and the C part checks on a program and
// gives the count of findings of the rule.
fn supply_count(prog: const u8[:], root: const u8[:], id: const u8[:]) -> i64 {
    sast::read_manifest(prog);
    var df: sast::Finding[>..] = [];
    sast::check_pins(root, df);
    sast::check_cparts(root, df);
    var n: i64 = 0;
    for f in df { if sast::reg_id_s[f.rule] == id { n = n + 1; } }
    return n;
}

// g602_lines gives the lines of the findings of G602 in the text.
fn g602_lines(src: const u8[:], out: i64[>..]&) {
    var o = sast::default_options();
    o.profile = sast::PROFILE_ALL;
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/a.goose", src, o, fs);
    let want = sast::reg_find("G602");
    for f in fs { if f.rule == want { out.push(f.line); } }
}

// site records one row of the table.
fn site(src: const u8[:], id: const u8[:], kind: i64) {
    site_src.push(src);
    site_id.push(id);
    site_kind.push(kind);
}

// bidi_src writes the source of a bidirectional control character into
// the buffer.
fn bidi_src(kind: i64, out: u8[>..]&) {
    put(out, "let x = \"");
    // The kind names the mark: 1 is U+202A, 2 is U+061C, 3 is U+200E
    // and 4 is U+200F.
    if kind == 1 { out.push(226); out.push(128); out.push(170); }
    else if kind == 2 { out.push(216); out.push(156); out.push(156); }
    else if kind == 3 { out.push(226); out.push(128); out.push(142); }
    else { out.push(226); out.push(128); out.push(143); }
    put(out, "\";\n");
}
