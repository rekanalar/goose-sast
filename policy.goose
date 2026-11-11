// The policy file: the banned packages, the allowed licences and the
// allowed sources. The file is JSON with the four sections of
// cargo-deny: bans, licenses, sources and advisories.
namespace sast;

import json;

// The policy of the last read. The bytes live in one buffer; the offset
// lists hold the range of each entry.
var pol_buf: u8[>..] = [];
// The banned package names.
var pol_ban_at: i64[>..] = [];
var pol_ban_end: i64[>..] = [];
// The banned ranges: a package name and a range, side by side.
var pol_banver_name_at: i64[>..] = [];
var pol_banver_name_end: i64[>..] = [];
var pol_banver_range_at: i64[>..] = [];
var pol_banver_range_end: i64[>..] = [];
// The allowed licences.
var pol_lic_at: i64[>..] = [];
var pol_lic_end: i64[>..] = [];
// The licence of each package.
var pol_perdep_at: i64[>..] = [];
var pol_perdep_end: i64[>..] = [];
var pol_perdep_lic_at: i64[>..] = [];
var pol_perdep_lic_end: i64[>..] = [];
// The allowed sources.
var pol_src_at: i64[>..] = [];
var pol_src_end: i64[>..] = [];
// The allowed advisories: the ID and the reason.
var pol_ign_at: i64[>..] = [];
var pol_ign_end: i64[>..] = [];
var pol_ign_reason_at: i64[>..] = [];
var pol_ign_reason_end: i64[>..] = [];
// Whether the policy demands a licence for every package.
var pol_lic_required = false;

// pol_reset empties the policy.
fn pol_reset() {
    pol_buf.resize(0, 0);
    pol_ban_at.resize(0, 0);
    pol_ban_end.resize(0, 0);
    pol_banver_name_at.resize(0, 0);
    pol_banver_name_end.resize(0, 0);
    pol_banver_range_at.resize(0, 0);
    pol_banver_range_end.resize(0, 0);
    pol_lic_at.resize(0, 0);
    pol_lic_end.resize(0, 0);
    pol_perdep_at.resize(0, 0);
    pol_perdep_end.resize(0, 0);
    pol_perdep_lic_at.resize(0, 0);
    pol_perdep_lic_end.resize(0, 0);
    pol_src_at.resize(0, 0);
    pol_src_end.resize(0, 0);
    pol_ign_at.resize(0, 0);
    pol_ign_end.resize(0, 0);
    pol_ign_reason_at.resize(0, 0);
    pol_ign_reason_end.resize(0, 0);
    pol_lic_required = false;
}

// pol_push copies one text into the policy buffer and gives its range.
fn pol_push(text: const u8[:]) -> i64, i64 {
    let at = pol_buf.len;
    for b in text { pol_buf.push(b); }
    return at, pol_buf.len;
}

// pol_banned reports whether a package name is on the ban list.
fn pol_banned(name: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < pol_ban_at.len {
        if pol_buf[pol_ban_at[i]..pol_ban_end[i]] == name { return true; }
        i = i + 1;
    }
    return false;
}

// pol_banver gives the range of the banned version of a package. It
// gives an empty text when the package holds no banned range.
fn pol_banver(name: const u8[:]) -> const u8[:] {
    var i: i64 = 0;
    while i < pol_banver_name_at.len {
        if pol_buf[pol_banver_name_at[i]..pol_banver_name_end[i]] == name {
            return pol_buf[pol_banver_range_at[i]..pol_banver_range_end[i]];
        }
        i = i + 1;
    }
    return "";
}

// pol_licence_allowed reports whether a licence is on the allow list.
fn pol_licence_allowed(lic: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < pol_lic_at.len {
        if pol_buf[pol_lic_at[i]..pol_lic_end[i]] == lic { return true; }
        i = i + 1;
    }
    return false;
}

// pol_licence_of gives the licence of a package. It gives an empty text
// when the policy names none.
fn pol_licence_of(name: const u8[:]) -> const u8[:] {
    var i: i64 = 0;
    while i < pol_perdep_at.len {
        if pol_buf[pol_perdep_at[i]..pol_perdep_end[i]] == name {
            return pol_buf[pol_perdep_lic_at[i]..pol_perdep_lic_end[i]];
        }
        i = i + 1;
    }
    return "";
}

// pol_source_allowed reports whether a source is on the allow list. An
// entry names a source registry, so it matches the source and the
// packages under it.
fn pol_source_allowed(src: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < pol_src_at.len {
        let want = pol_buf[pol_src_at[i]..pol_src_end[i]];
        if want.len == 0 { continue; }
        if src == want { return true; }
        if src.len > want.len && src[0..want.len] == want
            && src[want.len] == 47 { return true; }
        i = i + 1;
    }
    return false;
}

// pol_ignores reports whether an advisory ID is on the ignore list.
fn pol_ignores(id: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < pol_ign_at.len {
        if pol_buf[pol_ign_at[i]..pol_ign_end[i]] == id { return true; }
        i = i + 1;
    }
    return false;
}

// read_policy reads the policy text. It gives false on a fault, with
// the message in err.
fn read_policy(text: const u8[:], err: u8[>..]&) -> bool {
    pol_reset();
    var scratch: u8[>..] = [];
    var r = json::reader(text);
    json::each_member(r) { key =>
        if key == "bans" {
            read_bans(r, scratch);
        } else if key == "licenses" || key == "licences" {
            read_licenses(r, scratch);
        } else if key == "sources" {
            read_sources(r, scratch);
        } else if key == "advisories" {
            read_advisory_policy(r, scratch);
        } else {
            json::skip(r);
        }
    };
    if !json::finish(r) {
        for b in json::message(r) { err.push(b); }
        return false;
    }
    return true;
}

// read_bans reads the bans section.
fn read_bans(r: json::Reader&, scratch: u8[>..]&) {
    json::each_member(r) { key =>
        if key == "deny" {
            json::each_element(r) {
                let s = json::read_string(r, scratch);
                let a, b = pol_push(s);
                pol_ban_at.push(a);
                pol_ban_end.push(b);
            };
        } else if key == "deny_versions" {
            json::each_member(r) { name =>
                let s = json::read_string(r, scratch);
                let a, b = pol_push(name);
                pol_banver_name_at.push(a);
                pol_banver_name_end.push(b);
                let c, d = pol_push(s);
                pol_banver_range_at.push(c);
                pol_banver_range_end.push(d);
            };
        } else {
            json::skip(r);
        }
    };
}

// read_licenses reads the licenses section.
fn read_licenses(r: json::Reader&, scratch: u8[>..]&) {
    json::each_member(r) { key =>
        if key == "allow" {
            json::each_element(r) {
                let s = json::read_string(r, scratch);
                let a, b = pol_push(s);
                pol_lic_at.push(a);
                pol_lic_end.push(b);
            };
        } else if key == "require" {
            pol_lic_required = json::read_bool(r);
        } else if key == "per_dep" {
            json::each_member(r) { name =>
                let s = json::read_string(r, scratch);
                let a, b = pol_push(name);
                pol_perdep_at.push(a);
                pol_perdep_end.push(b);
                let c, d = pol_push(s);
                pol_perdep_lic_at.push(c);
                pol_perdep_lic_end.push(d);
            };
        } else {
            json::skip(r);
        }
    };
}

// read_sources reads the sources section.
fn read_sources(r: json::Reader&, scratch: u8[>..]&) {
    json::each_member(r) { key =>
        if key == "allow" {
            json::each_element(r) {
                let s = json::read_string(r, scratch);
                let a, b = pol_push(s);
                pol_src_at.push(a);
                pol_src_end.push(b);
            };
        } else {
            json::skip(r);
        }
    };
}

// read_advisory_policy reads the advisories section of the policy.
fn read_advisory_policy(r: json::Reader&, scratch: u8[>..]&) {
    json::each_member(r) { key =>
        if key == "ignore" {
            json::each_element(r) {
                json::each_member(r) { ikey =>
                    if ikey == "id" {
                        let s = json::read_string(r, scratch);
                        let a, b = pol_push(s);
                        pol_ign_at.push(a);
                        pol_ign_end.push(b);
                    } else if ikey == "reason" {
                        let s = json::read_string(r, scratch);
                        let a, b = pol_push(s);
                        pol_ign_reason_at.push(a);
                        pol_ign_reason_end.push(b);
                    } else {
                        json::skip(r);
                    }
                };
            };
        } else {
            json::skip(r);
        }
    };
}
