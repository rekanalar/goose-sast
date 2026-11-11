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

// usage prints the flags of the command.
fn usage() {
    write_stderr("sast: a security linter for Goose source\n");
    write_stderr("usage: sast [flags] <path>\n");
    write_stderr("  -severity low|medium|high|critical   the lowest severity to report (default low)\n");
    write_stderr("  -confidence low|medium|high          the lowest confidence to report (default low)\n");
    write_stderr("  -exclude ID[,ID]                     the rule IDs to leave out\n");
    write_stderr("  -include ID[,ID]                     only these rule IDs\n");
    write_stderr("  -exclude-path NAME[,NAME]            path parts to skip in the walk\n");
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

    if !quiet {
        var out: u8[>..] = [];
        sast::format_text(findings[..], out);
        sast::format_summary(findings.len, scanned, skipped, out);
        write_stdout(out[..]);
    }
    if no_fail { exit(0); }
    if findings.len > 0 { exit(1); }
    exit(0);
}
