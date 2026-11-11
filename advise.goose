// The advisory file: the known defects of the packages. The file is
// JSON in the RustSec shape. The version ranges go through the semver
// module.
namespace sast;

import json;

// The advisories of the last read. The bytes live in one buffer; the
// offset lists hold the range of each field.
var adv_buf: u8[>..] = [];
var adv_id_at: i64[>..] = [];
var adv_id_end: i64[>..] = [];
var adv_pkg_at: i64[>..] = [];
var adv_pkg_end: i64[>..] = [];
var adv_range_at: i64[>..] = [];
var adv_range_end: i64[>..] = [];
var adv_sev_at: i64[>..] = [];
var adv_sev_end: i64[>..] = [];
var adv_title_at: i64[>..] = [];
var adv_title_end: i64[>..] = [];
var adv_patched_at: i64[>..] = [];
var adv_patched_end: i64[>..] = [];
var adv_patched_of: i64[>..] = [];

// adv_reset empties the advisory list.
fn adv_reset() {
    adv_buf.resize(0, 0);
    adv_id_at.resize(0, 0);
    adv_id_end.resize(0, 0);
    adv_pkg_at.resize(0, 0);
    adv_pkg_end.resize(0, 0);
    adv_range_at.resize(0, 0);
    adv_range_end.resize(0, 0);
    adv_sev_at.resize(0, 0);
    adv_sev_end.resize(0, 0);
    adv_title_at.resize(0, 0);
    adv_title_end.resize(0, 0);
    adv_patched_at.resize(0, 0);
    adv_patched_end.resize(0, 0);
    adv_patched_of.resize(0, 0);
}

// adv_push copies one text into the advisory buffer and gives its range.
fn adv_push(text: const u8[:]) -> i64, i64 {
    let at = adv_buf.len;
    for b in text { adv_buf.push(b); }
    return at, adv_buf.len;
}

// adv_count gives the count of advisories.
fn adv_count() -> i64 {
    return adv_id_at.len;
}

// adv_id gives the ID of the advisory i.
fn adv_id(i: i64) -> const u8[:] {
    return adv_buf[adv_id_at[i]..adv_id_end[i]];
}

// adv_package gives the package name of the advisory i.
fn adv_package(i: i64) -> const u8[:] {
    return adv_buf[adv_pkg_at[i]..adv_pkg_end[i]];
}

// adv_range gives the affected range of the advisory i.
fn adv_range(i: i64) -> const u8[:] {
    return adv_buf[adv_range_at[i]..adv_range_end[i]];
}

// adv_severity gives the severity of the advisory i.
fn adv_severity(i: i64) -> const u8[:] {
    return adv_buf[adv_sev_at[i]..adv_sev_end[i]];
}

// adv_title gives the title of the advisory i.
fn adv_title(i: i64) -> const u8[:] {
    return adv_buf[adv_title_at[i]..adv_title_end[i]];
}

// adv_patched gives the fixed version of the advisory i.
fn adv_patched(i: i64) -> const u8[:] {
    var k: i64 = 0;
    while k < adv_patched_of.len {
        if adv_patched_of[k] == i {
            return adv_buf[adv_patched_at[k]..adv_patched_end[k]];
        }
        k = k + 1;
    }
    return "";
}

// read_advisories reads the advisory text. It gives false on a fault,
// with the message in err.
fn read_advisories(text: const u8[:], err: u8[>..]&) -> bool {
    adv_reset();
    var scratch: u8[>..] = [];
    var r = json::reader(text);
    // The file holds a list under the key advisories, or the list
    // itself.
    if json::peek(r) == 91 {
        read_advisory_list(r, scratch);
    } else {
        json::each_member(r) { key =>
            if key == "advisories" {
                read_advisory_list(r, scratch);
            } else {
                json::skip(r);
            }
        };
    }
    if !json::finish(r) {
        for b in json::message(r) { err.push(b); }
        return false;
    }
    return true;
}

// read_advisory_list reads the advisories of a list.
fn read_advisory_list(r: json::Reader&, scratch: u8[>..]&) {
    json::each_element(r) {
        read_one_advisory(r, scratch);
    };
}

// read_one_advisory reads one advisory of the list.
fn read_one_advisory(r: json::Reader&, scratch: u8[>..]&) {
    var id_at: i64 = -1;
    var id_end: i64 = -1;
    var pkg_at: i64 = -1;
    var pkg_end: i64 = -1;
    var range_at: i64 = -1;
    var range_end: i64 = -1;
    var sev_at: i64 = -1;
    var sev_end: i64 = -1;
    var title_at: i64 = -1;
    var title_end: i64 = -1;
    var patched_at: i64 = -1;
    var patched_end: i64 = -1;
    json::each_member(r) { key =>
        if key == "id" {
            let s = json::read_string(r, scratch);
            let a, b = adv_push(s);
            id_at = a; id_end = b;
        } else if key == "package" {
            let s = json::read_string(r, scratch);
            let a, b = adv_push(s);
            pkg_at = a; pkg_end = b;
        } else if key == "versions" {
            // The versions field holds either a range text or a map with
            // a patched list.
            let s = json::read_string(r, scratch);
            let a, b = adv_push(s);
            range_at = a; range_end = b;
        } else if key == "severity" {
            let s = json::read_string(r, scratch);
            let a, b = adv_push(s);
            sev_at = a; sev_end = b;
        } else if key == "title" {
            let s = json::read_string(r, scratch);
            let a, b = adv_push(s);
            title_at = a; title_end = b;
        } else if key == "patched" {
            let s = json::read_string(r, scratch);
            let a, b = adv_push(s);
            patched_at = a; patched_end = b;
        } else {
            json::skip(r);
        }
    };
    if id_at < 0 { return; }
    adv_id_at.push(id_at);
    adv_id_end.push(id_end);
    adv_pkg_at.push(pkg_at);
    adv_pkg_end.push(pkg_end);
    adv_range_at.push(range_at);
    adv_range_end.push(range_end);
    adv_sev_at.push(sev_at);
    adv_sev_end.push(sev_end);
    adv_title_at.push(title_at);
    adv_title_end.push(title_end);
    if patched_at >= 0 {
        adv_patched_at.push(patched_at);
        adv_patched_end.push(patched_end);
        adv_patched_of.push(adv_id_at.len - 1);
    }
}

// semver_ok reports whether the range text is a range the semver module
// reads.
fn semver_ok(range: const u8[:]) -> bool {
    var norm: u8[>..] = [];
    return semver::valid_range(norm, range);
}

// range_hits reports whether the version text falls in the range text.
// The range may hold commas, as the RustSec ranges do; the semver
// module reads them with spaces.
fn range_hits(version: const u8[:], range: const u8[:]) -> bool {
    var v, ok = semver::parse(version);
    if !ok { return false; }
    var norm: u8[>..] = [];
    var i: i64 = 0;
    while i < range.len {
        if range[i] == 44 { norm.push(32); } else { norm.push(range[i]); }
        i = i + 1;
    }
    return semver::satisfies(v, norm[..]);
}
