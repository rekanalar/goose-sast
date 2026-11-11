// The dependency checks: the ban check, the licence check, the source
// check and the advisory check. They run over the manifest that the
// import lines form.
namespace sast;

// The rule IDs of the dependency checks. They follow the check names of
// cargo-deny.
const RULE_BAN: const u8[:] = "BAN";
const RULE_LICENCE: const u8[:] = "LICENSE";
const RULE_SOURCE: const u8[:] = "SOURCE";
const RULE_ADVISORY: const u8[:] = "ADVISORY";

// dep_findings holds the findings of the dependency checks of the last
// run, so the caller can read them after the checks.
var dep_findings: Finding[>..] = [];

// dep_report writes one dependency finding. The line and the column
// are 0, because a dependency has no place in a source file.
fn dep_report(out: Finding[>..]&, rule: i64, msg: const u8[:]) {
    let at = buf_texts.len;
    for b in msg { buf_texts.push(b); }
    out.push(Finding {
        rule: rule, sev: reg_sev_s[rule], conf: reg_conf_s[rule],
        cwe: reg_cwe_s[rule], file: add_path("<dependencies>"),
        line: 0, col: 0, msg: at, msg_end: buf_texts.len,
    });
}

// dep_msg writes the message of a dependency finding. It names the
// package and the tag.
fn dep_msg(out: u8[>..]&, name: const u8[:], tag: const u8[:], why: const u8[:]) {
    for b in name { out.push(b); }
    if tag.len > 0 {
        out.push(64);
        for b in tag { out.push(b); }
    }
    out.push(58);
    out.push(32);
    for b in why { out.push(b); }
}

// check_bans runs the ban check over the manifest. A banned package
// and a package in a banned range each report one finding.
fn check_bans(out: Finding[>..]&) -> i64 {
    let rule = reg_find(RULE_BAN);
    var found: i64 = 0;
    var i: i64 = 0;
    while i < dep_count() {
        let name = dep_name(i);
        let tag = dep_tag(i);
        if pol_banned(name) {
            var msg: u8[>..] = [];
            dep_msg(msg, name, tag, "the package is banned");
            dep_report(out, rule, msg[..]);
            found = found + 1;
        } else {
            let range = pol_banver(name);
            if range.len > 0 && tag.len > 0 && range_hits(tag, range) {
                var msg: u8[>..] = [];
                dep_msg(msg, name, tag, "the version is banned");
                dep_report(out, rule, msg[..]);
                found = found + 1;
            }
        }
        i = i + 1;
    }
    return found;
}

// check_licences runs the licence check over the manifest. A package
// with no licence is a finding when the policy demands one. A licence
// that is not on the allow list is a finding.
fn check_licences(out: Finding[>..]&) -> i64 {
    let rule = reg_find(RULE_LICENCE);
    var found: i64 = 0;
    var i: i64 = 0;
    while i < dep_count() {
        let name = dep_name(i);
        let tag = dep_tag(i);
        let lic = pol_licence_of(name);
        if lic.len == 0 {
            if pol_lic_required {
                var msg: u8[>..] = [];
                dep_msg(msg, name, tag, "the package holds no licence");
                dep_report(out, rule, msg[..]);
                found = found + 1;
            }
        } else if !pol_licence_allowed(lic) {
            var msg: u8[>..] = [];
            dep_msg(msg, name, tag, "the licence is not allowed");
            dep_report(out, rule, msg[..]);
            found = found + 1;
        }
        i = i + 1;
    }
    return found;
}

// check_sources runs the source check over the manifest. A source that
// is not on the allow list is a finding. An empty allow list allows
// every source.
fn check_sources(out: Finding[>..]&) -> i64 {
    let rule = reg_find(RULE_SOURCE);
    var found: i64 = 0;
    if pol_src_at.len == 0 { return 0; }
    var i: i64 = 0;
    while i < dep_count() {
        let name = dep_name(i);
        let tag = dep_tag(i);
        let src = dep_source(i);
        if !pol_source_allowed(src) {
            var msg: u8[>..] = [];
            dep_msg(msg, name, tag, "the source is not allowed");
            dep_report(out, rule, msg[..]);
            found = found + 1;
        }
        i = i + 1;
    }
    return found;
}

// check_advisories runs the advisory check over the manifest. An
// advisory whose package and range cover the pinned tag reports one
// finding. An advisory on the ignore list of the policy stays out.
fn check_advisories(out: Finding[>..]&) -> i64 {
    let rule = reg_find(RULE_ADVISORY);
    var found: i64 = 0;
    var i: i64 = 0;
    while i < dep_count() {
        let name = dep_name(i);
        let tag = dep_tag(i);
        if tag.len == 0 { i = i + 1; continue; }
        var k: i64 = 0;
        while k < adv_count() {
            let id = adv_id(k);
            if !pol_ignores(id) && adv_package(k) == name {
                let range = adv_range(k);
                if range.len > 0 && range_hits(tag, range) {
                    var msg: u8[>..] = [];
                    dep_msg(msg, name, tag, "the advisory ");
                    for b in id { msg.push(b); }
                    msg.push(32);
                    let title = adv_title(k);
                    if title.len > 0 {
                        for b in title { msg.push(b); }
                    } else {
                        for b in "covers the version" { msg.push(b); }
                    }
                    dep_report(out, rule, msg[..]);
                    found = found + 1;
                    break;
                }
            }
            k = k + 1;
        }
        i = i + 1;
    }
    return found;
}

// check_deps runs the manifest reader and the four dependency checks.
// It gives the count of findings.
fn check_deps(src: const u8[:], out: Finding[>..]&) -> i64 {
    read_manifest(src);
    var found: i64 = 0;
    found = found + check_bans(out);
    found = found + check_licences(out);
    found = found + check_sources(out);
    found = found + check_advisories(out);
    return found;
}
