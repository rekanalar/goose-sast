// sast: the security linter command.
//
// Build: goose build cmd/sast.goose -o sast
// Run:   sast [flags] <path>
//
// The command scans one file or a tree of .goose files and prints one
// line per finding. It exits 0 with no finding, 1 with findings and 2
// when the scan itself fails.
import std;
import os;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

// sev_of reads the name of a severity.
fn sev_of(name: const u8[:]) -> i64 {
    if name == "low" { return sast::SEV_LOW; }
    if name == "medium" { return sast::SEV_MEDIUM; }
    if name == "high" { return sast::SEV_HIGH; }
    if name == "critical" { return sast::SEV_CRITICAL; }
    return -1;
}

// split_list splits a list of IDs or paths on commas.
fn split_list(list: const u8[:], out: const u8[:][>..]&) {
    var at: i64 = 0;
    var i: i64 = 0;
    while i < list.len {
        if list[i] == 44 {
            if i > at { out.push(list[at..i]); }
            at = i + 1;
        }
        i = i + 1;
    }
    if list.len > at { out.push(list[at..list.len]); }
}

// parse_num reads a decimal number. It gives -1 for anything else.
fn parse_num(s: const u8[:]) -> i64 {
    if s.len == 0 || s.len > 9 { return -1; }
    var n: i64 = 0;
    for b in s {
        if b < 48 || b > 57 { return -1; }
        n = n * 10 + (b - 48);
    }
    return n;
}

// usage prints the flags of the command.
fn usage() {
    write_stderr("sast: a security linter for Goose source\n");
    write_stderr("usage: sast [flags] <path>\n");
    write_stderr("  -severity low|medium|high|critical   the lowest severity to report (default low)\n");
    write_stderr("  -confidence low|medium|high          the lowest confidence to report (default low)\n");
    write_stderr("  -exclude ID[,ID]                     the rule IDs to leave out\n");
    write_stderr("  -include ID[,ID]                     only these rule IDs\n");
    write_stderr("  -exclude-path NAME[,NAME]            path parts to skip in the walk\n");
    write_stderr("  -f text|json                         the output format (default text)\n");
    write_stderr("  -max-depth N                        the directory levels the walk reads\n");
    write_stderr("  -max-files N                        the files the walk reads\n");
    write_stderr("  -rules FILE                         load custom rules from this file\n");
    write_stderr("  -policy FILE                        run the dependency checks with this policy\n");
    write_stderr("  -advisories FILE                    run the advisory check with this file\n");
    write_stderr("  -quiet                               no output but the exit code\n");
    write_stderr("  -no-fail                             always exit 0\n");
    write_stderr("  -list-rules                          print the rule list and exit\n");
}

// die prints a fault of the scan and ends with exit code 2.
fn die(msg: const u8[:]) {
    write_stderr("sast: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

// put_slice appends the bytes of s.
fn put_slice(out: u8[>..]&, s: const u8[:]) {
    for b in s { out.push(b); }
}

// opt_push_target copies one target path into the target buffer and
// holds its range. The arg text does not outlive the loop.
var tgt_buf: u8[>..] = [];
var tgt_at: i64[>..] = [];
var tgt_end: i64[>..] = [];
fn opt_push_target(s: const u8[:]) {
    tgt_at.push(tgt_buf.len);
    for b in s { tgt_buf.push(b); }
    tgt_end.push(tgt_buf.len);
}

// target_at gives the path of the target i.
fn target_at(i: i64) -> const u8[:] {
    return tgt_buf[tgt_at[i]..tgt_end[i]];
}

// main runs one scan.
fn main() {
    var o = sast::default_options();
    var quiet = false;
    var no_fail = false;
    var list_rules = false;
    var json_out = false;
    var policy_path: u8[>..] = [];
    var adv_path: u8[>..] = [];
    var have_policy = false;
    var rules_path: u8[>..] = [];
    var have_rules = false;
    var have_adv = false;
    var target_count: i64 = 0;
    var bad: u8[>..] = [];

    var i: i64 = 1;
    while i < arg_count() {
        var a: u8[>..] = [];
        arg(i, a);
        if a[..] == "-severity" || a[..] == "-confidence" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            let lvl = sev_of(v[..]);
            if lvl < 0 { die("the flag takes low, medium, high or critical"); }
            if a[..] == "-severity" { o.min_severity = lvl; }
            else { o.min_confidence = lvl; }
        } else if a[..] == "-exclude" || a[..] == "-include" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            var ids: const u8[:][>..] = [];
            split_list(v[..], ids);
            var k: i64 = 0;
            while k < ids.len {
                if sast::reg_find(ids[k]) < 0 {
                    format(bad, "no rule carries the ID ", ids[k], "\n");
                }
                if a[..] == "-exclude" { sast::opt_exclude(ids[k]); }
                else { sast::opt_include(ids[k]); }
                k = k + 1;
            }
        } else if a[..] == "-exclude-path" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            var parts: const u8[:][>..] = [];
            split_list(v[..], parts);
            var k: i64 = 0;
            while k < parts.len {
                sast::opt_skip_path(parts[k]);
                k = k + 1;
            }
        } else if a[..] == "-f" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            if v[..] == "json" { json_out = true; }
            else if v[..] == "text" { json_out = false; }
            else { die("the format is text or json"); }
        } else if a[..] == "-max-depth" || a[..] == "-max-files" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            let n = parse_num(v[..]);
            if n < 0 { die("the flag takes a number"); }
            if a[..] == "-max-depth" { o.max_depth = n; }
            else { o.max_files = n; }
        } else if a[..] == "-rules" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            for b in v { rules_path.push(b); }
            have_rules = true;
        } else if a[..] == "-policy" || a[..] == "-advisories" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            if a[..] == "-policy" {
                for b in v { policy_path.push(b); }
                have_policy = true;
            } else {
                for b in v { adv_path.push(b); }
                have_adv = true;
            }
        } else if a[..] == "-quiet" {
            quiet = true;
        } else if a[..] == "-no-fail" {
            no_fail = true;
        } else if a[..] == "-list-rules" {
            list_rules = true;
        } else if a[..] == "-h" || a[..] == "-help" || a[..] == "--help" {
            usage();
            exit(0);
        } else if a.len > 0 && a[0] == 45 {
            format(bad, "no flag holds the name ", a[..], "\n");
        } else {
            opt_push_target(a[..]);
            target_count = target_count + 1;
        }
        i = i + 1;
    }

    if bad.len > 0 { die(bad[..]); }

    if list_rules {
        var out: u8[>..] = [];
        sast::list_rules(out);
        write_stdout(out[..]);
        exit(0);
    }

    if target_count != 1 {
        usage();
        exit(2);
    }

    if have_rules {
        var rules_text: u8[>..] = [];
        var rerr: u8[>..] = [];
        if !read_file(rules_path[..], rules_text) {
            die("cannot read the rules file");
        }
        if !sast::read_custom(rules_text[..], rerr) { die(rerr[..]); }
    }

    var findings: sast::Finding[>..] = [];
    var scanned: i64 = 0;
    var skipped: i64 = 0;
    let dir_mode = is_dir(target_at(0));
    if dir_mode {
        scanned, skipped = sast::scan_dir(target_at(0), o, findings);
    } else {
        var src: u8[>..] = [];
        if !read_file(target_at(0), src) {
            die("cannot read the file");
        }
        if src.len > o.max_file {
            die("the file is above the size bound");
        }
        sast::scan_text(target_at(0), src[..], o, findings);
        sast::sort_findings(findings);
        scanned = 1;
    }

    var dep_bits: i64 = 0;
    if have_policy || have_adv {
        var policy_text: u8[>..] = [];
        var perr: u8[>..] = [];
        if have_policy {
            if !read_file(policy_path[..], policy_text) {
                die("cannot read the policy file");
            }
            if !sast::read_policy(policy_text[..], perr) { die(perr[..]); }
        }
        var adv_text: u8[>..] = [];
        if have_adv {
            if !read_file(adv_path[..], adv_text) {
                die("cannot read the advisory file");
            }
            if !sast::read_advisories(adv_text[..], perr) { die(perr[..]); }
        }
        // The manifest is the import lines of the file that was scanned.
        var root_src: u8[>..] = [];
        if !read_file(target_at(0), root_src) { die("cannot read the file"); }
        var df: sast::Finding[>..] = [];
        sast::findings_reset();
        sast::check_deps(root_src[..], df);
        // The bitset of cargo-deny: advisories 1, bans 2, licenses 4,
        // sources 8.
        var i2: i64 = 0;
        while i2 < df.len {
            let rid = sast::reg_id_s[df[i2].rule];
            if rid == "ADVISORY" { dep_bits = dep_bits | 1; }
            else if rid == "BAN" { dep_bits = dep_bits | 2; }
            else if rid == "LICENSE" { dep_bits = dep_bits | 4; }
            else if rid == "SOURCE" { dep_bits = dep_bits | 8; }
            i2 = i2 + 1;
        }
        for f in df { findings.push(f); }
    }

    if !quiet {
        var out: u8[>..] = [];
        if json_out {
            sast::format_json(findings[..], scanned, skipped, out);
        } else {
            sast::format_text(findings[..], out);
            sast::format_summary(findings.len, scanned, skipped, out);
        }
        write_stdout(out[..]);
    }
    if no_fail { exit(0); }
    if dep_bits > 0 { exit(dep_bits); }
    if findings.len > 0 { exit(1); }
    exit(0);
}
