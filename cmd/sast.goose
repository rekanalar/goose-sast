// sast: the security linter command.
//
// Build: goose build cmd/sast.goose -o sast
// Run:   sast [flags] <path> [<path>...]
//
// The command scans one file or a tree of .goose files and prints one
// line per finding. It exits 0 with no finding, 1 with findings and 2
// when the scan itself fails.
import std;
import os;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

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
    write_stderr("usage: sast [flags] <path> [<path>...]\n");
    write_stderr("  -severity low|medium|high|critical   the lowest severity to report (default low)\n");
    write_stderr("  -confidence low|medium|high          the lowest confidence to report (default low)\n");
    write_stderr("  -exclude ID[,ID]                     the rule IDs to leave out\n");
    write_stderr("  -include ID[,ID]                     only these rule IDs\n");
    write_stderr("  -exclude-path NAME[,NAME]            path parts to skip in the walk\n");
    write_stderr("  -f text|json|sarif                         the output format (default text)\n");
    write_stderr("  -max-depth N                        the directory levels the walk reads\n");
    write_stderr("  -max-files N                        the files the walk reads\n");
    write_stderr("  -rules FILE                         load custom rules from this file\n");
    write_stderr("  -config FILE                        read the settings of the run from this file\n");
    write_stderr("  -no-config                          do not read .goose-sast.json\n");
    write_stderr("  -policy FILE                        run the dependency checks with this policy\n");
    write_stderr("  -advisories FILE                    run the advisory check with this file\n");
    write_stderr("  -quiet                               no output but the exit code\n");
    write_stderr("  -no-fail                             always exit 0\n");
    write_stderr("  -list-rules                          print the rule list and exit\n");
}

// esc_control writes the bytes of s to out. A byte outside printable
// ASCII appears as a \xNN escape, except the newline. The bytes above
// 126 include the UTF-8 form of the C1 controls, and a terminal may
// read those as a control sequence. put_escaped in format.goose does
// the same for the findings.
fn esc_control(out: u8[>..]&, s: const u8[:]) {
    let digits = "0123456789abcdef";
    var i: i64 = 0;
    while i < s.len {
        let b = s[i];
        if (b < 32 && b != 10) || b > 126 {
            out.push(92);
            out.push(120);
            out.push(digits[(b >> 4) as i64]);
            out.push(digits[(b & 15) as i64]);
        } else {
            out.push(b);
        }
        i = i + 1;
    }
}

// die prints a fault of the scan and ends with exit code 2.
fn die(msg: const u8[:]) {
    var out: u8[>..] = [];
    esc_control(out, msg);
    write_stderr("sast: ");
    write_stderr(out[..]);
    if out.len == 0 || out[out.len - 1] != 10 {
        write_stderr("\n");
    }
    exit(2);
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

// The rule files of the run. The bytes live in one buffer and the two
// offset lists hold the range of each file.
var rules_buf: u8[>..] = [];
var rules_at: i64[>..] = [];
var rules_end: i64[>..] = [];

// rules_push copies one rule file into the buffer.
fn rules_push(s: const u8[:]) {
    rules_at.push(rules_buf.len);
    for b in s { rules_buf.push(b); }
    rules_end.push(rules_buf.len);
}

// rules_file gives the path of the rule file i.
fn rules_file(i: i64) -> const u8[:] {
    return rules_buf[rules_at[i]..rules_end[i]];
}

// The count of the targets and the count of the rule files of a run
// are bounded. A command with a long list ends with a fault.
const MAX_TARGETS: i64 = 64;
const MAX_RULES: i64 = 64;

// first_file_target gives the path of the first target that is a file.
// The dependency checks read that file. A run with no file target
// leaves the checks out.
fn first_file_target() -> const u8[:] {
    var t: i64 = 0;
    while t < tgt_at.len {
        let path = target_at(t);
        if !is_dir(path) { return path; }
        t = t + 1;
    }
    return "";
}

// main runs one scan.
fn main() {
    var o = sast::default_options();
    var quiet = false;
    var no_fail = false;
    var list_rules = false;
    var json_out = false;
    var sarif_out = false;
    var policy_path: u8[>..] = [];
    var adv_path: u8[>..] = [];
    var config_path: u8[>..] = [];
    var have_config = false;
    var no_config = false;
    var target_count: i64 = 0;
    // The bits of the settings that the command line set. A setting
    // with its bit set keeps the value of the command line and the
    // config file does not change it.
    var mask: i64 = 0;
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
            if a[..] == "-severity" {
                let lvl = sast::sev_of_name(v[..]);
                if lvl < 0 { die("the flag takes low, medium, high or critical"); }
                o.min_severity = lvl;
                mask = mask | sast::CFG_SEV;
            } else {
                let lvl = sast::conf_of_name(v[..]);
                if lvl < 0 { die("the flag takes low, medium or high"); }
                o.min_confidence = lvl;
                mask = mask | sast::CFG_CONF;
            }
        } else if a[..] == "-exclude" || a[..] == "-include" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            var ids: const u8[:][>..] = [];
            sast::split_list(v[..], ids);
            if a[..] == "-exclude" { mask = mask | sast::CFG_EXCL; }
            else { mask = mask | sast::CFG_INCL; }
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
            sast::split_list(v[..], parts);
            mask = mask | sast::CFG_PATH;
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
            else if v[..] == "sarif" { sarif_out = true; }
            else if v[..] == "text" { json_out = false; }
            else { die("the format is text, json or sarif"); }
        } else if a[..] == "-max-depth" || a[..] == "-max-files" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            let n = parse_num(v[..]);
            if n < 0 { die("the flag takes a number"); }
            if a[..] == "-max-depth" {
                o.max_depth = n;
                mask = mask | sast::CFG_DEPTH;
            } else {
                o.max_files = n;
                mask = mask | sast::CFG_FILES;
            }
        } else if a[..] == "-rules" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            rules_push(v[..]);
        } else if a[..] == "-config" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            for b in v { config_path.push(b); }
            have_config = true;
        } else if a[..] == "-policy" || a[..] == "-advisories" {
            i = i + 1;
            if i >= arg_count() { die("the flag needs a value"); }
            var v: u8[>..] = [];
            arg(i, v);
            if a[..] == "-policy" {
                for b in v { policy_path.push(b); }
                mask = mask | sast::CFG_POLICY;
            } else {
                for b in v { adv_path.push(b); }
                mask = mask | sast::CFG_ADV;
            }
        } else if a[..] == "-no-config" {
            no_config = true;
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
            if target_count > MAX_TARGETS { die("too many targets"); }
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

    if target_count < 1 {
        usage();
        exit(2);
    }

    // The config file holds the settings that no flag set. The file of
    // the current directory is read when no flag names another file.
    var cfg_text: u8[>..] = [];
    var cfg_rules: u8[>..] = [];
    var cfg_err: u8[>..] = [];
    var have_cfg = false;
    if have_config {
        if !sast::read_bounded(config_path[..], o.max_file, cfg_text) {
            die("cannot read the config file: it is no regular file, it is above the size bound or it is unreadable");
        }
        have_cfg = true;
    } else if !no_config
        && sast::read_bounded(".goose-sast.json", o.max_file, cfg_text) {
        have_cfg = true;
    }
    if have_cfg {
        if !sast::read_config(cfg_text[..], mask, o, policy_path, adv_path,
                              cfg_rules, cfg_err) {
            die(cfg_err[..]);
        }
        if cfg_rules.len > 0 {
            var parts: const u8[:][>..] = [];
            sast::split_list(cfg_rules[..], parts);
            var k: i64 = 0;
            while k < parts.len {
                rules_push(parts[k]);
                k = k + 1;
            }
        }
    }
    if rules_at.len > MAX_RULES { die("too many rule files"); }

    // The rule files of the run merge. The first file resets the
    // registry and the later files add their rules to it.
    sast::custom_reset();
    var rk: i64 = 0;
    while rk < rules_at.len {
        var rules_text: u8[>..] = [];
        var rerr: u8[>..] = [];
        if !sast::read_bounded(rules_file(rk), o.max_file, rules_text) {
            die("cannot read the rules file: it is no regular file, it is above the size bound or it is unreadable");
        }
        if !sast::read_custom_more(rules_text[..], rerr) { die(rerr[..]); }
        rk = rk + 1;
    }

    var findings: sast::Finding[>..] = [];
    var scanned: i64 = 0;
    var skipped: i64 = 0;
    var budget = o.max_files;
    sast::scan_reset();
    var t: i64 = 0;
    while t < target_count {
        let path = target_at(t);
        if is_dir(path) {
            let s, k = sast::scan_dir_budget(path, o, findings, budget);
            scanned = scanned + s;
            skipped = skipped + k;
        } else if budget <= 0 {
            skipped = skipped + 1;
        } else {
            var src: u8[>..] = [];
            if !sast::read_bounded(path, o.max_file, src) {
                var msg: u8[>..] = [];
                format(msg, "cannot read the target ", path);
                die(msg[..]);
            }
            sast::scan_text(path, src[..], o, findings);
            scanned = scanned + 1;
            budget = budget - 1;
        }
        t = t + 1;
    }
    sast::sort_findings(findings);
    if sast::findings_hit_cap {
        write_stderr("sast: the run reached the bound of the findings; the count is a lower bound\n");
    }

    var dep_bits: i64 = 0;
    if policy_path.len > 0 || adv_path.len > 0 {
        var policy_text: u8[>..] = [];
        var perr: u8[>..] = [];
        if policy_path.len > 0 {
            if !sast::read_bounded(policy_path[..], o.max_file, policy_text) {
                die("cannot read the policy file");
            }
            if !sast::read_policy(policy_text[..], perr) { die(perr[..]); }
        }
        var adv_text: u8[>..] = [];
        if adv_path.len > 0 {
            if !sast::read_bounded(adv_path[..], o.max_file, adv_text) {
                die("cannot read the advisory file");
            }
            if !sast::read_advisories(adv_text[..], perr) { die(perr[..]); }
        }
        // The manifest is the import lines of the first file target.
        var root = first_file_target();
        var df: sast::Finding[>..] = [];
        if root.len > 0 {
            var root_src: u8[>..] = [];
            if !sast::read_bounded(root, o.max_file, root_src) { die("cannot read the file"); }
            // The store keeps the findings of the scan. The check adds
            // to it, so the path table stays valid.
            sast::check_deps(root_src[..], df);
            for f in df { findings.push(f); }
        }
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
    }

    if !quiet {
        var out: u8[>..] = [];
        if sarif_out {
            sast::format_sarif(findings[..], out);
        } else if json_out {
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
