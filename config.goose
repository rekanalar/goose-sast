// The config file: the settings of a run in one JSON object. The
// command reads the file and hands the text to this module. The module
// fills the options and the ID lists of the run. A setting whose bit
// is set in the mask keeps the value of the command line.
namespace sast;

import json;

// The bits of the settings that the command line set.
const CFG_SEV: i64 = 1;
const CFG_CONF: i64 = 2;
const CFG_EXCL: i64 = 4;
const CFG_INCL: i64 = 8;
const CFG_PATH: i64 = 16;
const CFG_FILES: i64 = 32;
const CFG_DEPTH: i64 = 64;
const CFG_POLICY: i64 = 128;
const CFG_ADV: i64 = 256;
const CFG_RULES: i64 = 512;

// conf_of_name gives the confidence of a name. It gives -1 when no
// confidence carries the name.
fn conf_of_name(name: const u8[:]) -> i64 {
    if name == "low" { return CONF_LOW; }
    if name == "medium" { return CONF_MEDIUM; }
    if name == "high" { return CONF_HIGH; }
    return -1;
}

// config_bad writes the message of a fault of the config file. The
// message names the key and the value that the key takes.
fn config_bad(err: u8[>..]&, key: const u8[:], want: const u8[:]) {
    format(err, "the config key ", key, " takes ", want, "\n");
}

// split_list splits a list of IDs or paths on commas. An empty part
// stays out. The parts point into the text of the caller.
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

// apply_ids applies a list of rule IDs. The list holds IDs that
// commas separate. An ID that no rule carries is a fault.
fn apply_ids(list: const u8[:], excl: bool, err: u8[>..]&) -> bool {
    var parts: const u8[:][>..] = [];
    split_list(list, parts);
    var k: i64 = 0;
    while k < parts.len {
        if reg_find(parts[k]) < 0 {
            format(err, "no rule carries the ID ", parts[k], "\n");
            return false;
        }
        if excl { opt_exclude(parts[k]); } else { opt_include(parts[k]); }
        k = k + 1;
    }
    return true;
}

// config_paths applies a list of path parts. The list holds parts that
// commas separate.
fn config_paths(list: const u8[:]) {
    var parts: const u8[:][>..] = [];
    split_list(list, parts);
    var k: i64 = 0;
    while k < parts.len {
        opt_skip_path(parts[k]);
        k = k + 1;
    }
}

// cfg_str reads the value of a key that holds a string. It gives the
// value and whether the read was good. A value of another shape is a
// fault that names the key.
fn cfg_str(r: json::Reader&, scratch: u8[>..]&, key: const u8[:],
           want: const u8[:], err: u8[>..]&) -> const u8[:], bool {
    let v = json::read_string(r, scratch);
    if r.error.len > 0 {
        config_bad(err, key, want);
        return "", false;
    }
    return v, true;
}

// The largest number that the config file may hold for a bound. The
// flags of the command take no more than nine digits, so the file
// takes no more either.
const CFG_MAX_NUM: i64 = 999999999;

// cfg_list reads the value of a key that holds a string of parts. It
// appends the bytes to out unless a flag of the command line owns the
// key. A value of the wrong shape is a fault that names the key.
fn cfg_list(r: json::Reader&, scratch: u8[>..]&, key: const u8[:],
            want: const u8[:], bit: i64, mask: i64, out: u8[>..]&,
            err: u8[>..]&) -> bool {
    let v, ok = cfg_str(r, scratch, key, want, err);
    if !ok { return false; }
    if (mask & bit) == 0 {
        for b in v { out.push(b); }
    }
    return true;
}

// cfg_num reads the value of a key that holds a number. It gives the
// value and whether the read was good. A value of another shape is a
// fault that names the key.
fn cfg_num(r: json::Reader&, key: const u8[:], err: u8[>..]&) -> i64, bool {
    let v = json::read_int(r);
    if r.error.len > 0 {
        config_bad(err, key, "a number");
        return 0, false;
    }
    if v > CFG_MAX_NUM {
        config_bad(err, key, "a number of at most nine digits");
        return 0, false;
    }
    return v, true;
}

// config_bit gives the bit of a key of the config file. It gives 0
// for a key that the file does not know.
fn config_bit(key: const u8[:]) -> i64 {
    if key == "min_severity" { return CFG_SEV; }
    if key == "min_confidence" { return CFG_CONF; }
    if key == "exclude" { return CFG_EXCL; }
    if key == "include" { return CFG_INCL; }
    if key == "exclude_path" { return CFG_PATH; }
    if key == "max_files" { return CFG_FILES; }
    if key == "max_depth" { return CFG_DEPTH; }
    if key == "policy" { return CFG_POLICY; }
    if key == "advisories" { return CFG_ADV; }
    if key == "rules" { return CFG_RULES; }
    return 0;
}

// read_config reads the text of a config file. It fills the options
// of the run and the ID lists. The paths of the policy file, of the
// advisory file and of the rule files go into the buffers of the
// caller. A value of the wrong shape is a fault and the message names
// the key. A key that the command does not know is a fault too.
fn read_config(text: const u8[:], mask: i64, o: Options&,
               policy: u8[>..]&, adv: u8[>..]&, rules: u8[>..]&,
               err: u8[>..]&) -> bool {
    var r = json::reader(text);
    var scratch: u8[>..] = [];
    var bad = false;
    var sev: i64 = -1;
    var conf: i64 = -1;
    var files: i64 = -1;
    var depth: i64 = -1;
    var excl: u8[>..] = [];
    var incl: u8[>..] = [];
    var paths: u8[>..] = [];
    // The bits of the keys that the file held. A key that comes twice
    // is a fault that names the key.
    var seen: i64 = 0;
    json::each_member(r) { key =>
        let bit = config_bit(key);
        if (seen & bit) != 0 {
            format(err, "the config key ", key, " appears twice\n");
            return false;
        }
        seen = seen | bit;
        if key == "min_severity" {
            let v, ok = cfg_str(r, scratch, "min_severity", "a name", err);
            if !ok {
                bad = true;
            } else {
                let lvl = sev_of_name(v);
                if lvl < 0 {
                    config_bad(err, "min_severity",
                        "low, medium, high or critical");
                    bad = true;
                } else if (mask & bit) == 0 { sev = lvl; }
            }
        } else if key == "min_confidence" {
            let v, ok = cfg_str(r, scratch, "min_confidence", "a name", err);
            if !ok {
                bad = true;
            } else {
                let lvl = conf_of_name(v);
                if lvl < 0 {
                    config_bad(err, "min_confidence", "low, medium or high");
                    bad = true;
                } else if (mask & bit) == 0 { conf = lvl; }
            }
        } else if key == "exclude" {
            if !cfg_list(r, scratch, "exclude", "a list of rule IDs", bit,
                         mask, excl, err) { bad = true; }
        } else if key == "include" {
            if !cfg_list(r, scratch, "include", "a list of rule IDs", bit,
                         mask, incl, err) { bad = true; }
        } else if key == "exclude_path" {
            if !cfg_list(r, scratch, "exclude_path", "a list of path parts",
                         bit, mask, paths, err) { bad = true; }
        } else if key == "policy" {
            if !cfg_list(r, scratch, "policy", "a path", bit, mask, policy,
                         err) { bad = true; }
        } else if key == "advisories" {
            if !cfg_list(r, scratch, "advisories", "a path", bit, mask, adv,
                         err) { bad = true; }
        } else if key == "rules" {
            // The rule files of the config file join the rule files of
            // the command line. The merge of the rule files is the rule
            // of the package.
            if !cfg_list(r, scratch, "rules", "a list of paths", 0, mask,
                         rules, err) { bad = true; }
        } else if key == "max_files" {
            let v, ok = cfg_num(r, "max_files", err);
            if !ok {
                bad = true;
            } else if v < 0 {
                config_bad(err, "max_files", "a number of files");
                bad = true;
            } else if (mask & bit) == 0 { files = v; }
        } else if key == "max_depth" {
            let v, ok = cfg_num(r, "max_depth", err);
            if !ok {
                bad = true;
            } else if v < 0 {
                config_bad(err, "max_depth", "a number of levels");
                bad = true;
            } else if (mask & bit) == 0 { depth = v; }
        } else {
            format(err, "the config file holds the unknown key ", key, "\n");
            bad = true;
            json::skip(r);
        }
    };
    if bad { return false; }
    if !json::finish(r) {
        for b in json::message(r) { err.push(b); }
        return false;
    }
    if sev >= 0 { o.min_severity = sev; }
    if conf >= 0 { o.min_confidence = conf; }
    if files >= 0 { o.max_files = files; }
    if depth >= 0 { o.max_depth = depth; }
    if excl.len > 0 && !apply_ids(excl[..], true, err) { return false; }
    if incl.len > 0 && !apply_ids(incl[..], false, err) { return false; }
    if paths.len > 0 { config_paths(paths[..]); }
    return true;
}
