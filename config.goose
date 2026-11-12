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

// config_ids applies a list of rule IDs. The list holds IDs that
// commas separate. An ID that no rule carries is a fault that names
// the key.
fn config_ids(list: const u8[:], key: const u8[:], excl: bool,
              err: u8[>..]&) -> bool {
    var at: i64 = 0;
    var i: i64 = 0;
    while i <= list.len {
        if i == list.len || list[i] == 44 {
            if i > at {
                let id = list[at..i];
                if reg_find(id) < 0 {
                    format(err, "the config key ", key, " holds the ID ",
                        id, " that no rule carries\n");
                    return false;
                }
                if excl { opt_exclude(id); } else { opt_include(id); }
            }
            at = i + 1;
        }
        i = i + 1;
    }
    return true;
}

// config_paths applies a list of path parts. The list holds parts that
// commas separate.
fn config_paths(list: const u8[:]) {
    var at: i64 = 0;
    var i: i64 = 0;
    while i <= list.len {
        if i == list.len || list[i] == 44 {
            if i > at { opt_skip_path(list[at..i]); }
            at = i + 1;
        }
        i = i + 1;
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

// cfg_num reads the value of a key that holds a number. It gives the
// value and whether the read was good. A value of another shape is a
// fault that names the key.
fn cfg_num(r: json::Reader&, key: const u8[:], err: u8[>..]&) -> i64, bool {
    let v = json::read_int(r);
    if r.error.len > 0 {
        config_bad(err, key, "a number");
        return 0, false;
    }
    return v, true;
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
    json::each_member(r) { key =>
        if key == "min_severity" {
            let v, ok = cfg_str(r, scratch, "min_severity", "a name", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_SEV) == 0 {
                let lvl = sev_of_name(v);
                if lvl < 0 {
                    config_bad(err, "min_severity",
                        "low, medium, high or critical");
                    bad = true;
                } else { sev = lvl; }
            }
        } else if key == "min_confidence" {
            let v, ok = cfg_str(r, scratch, "min_confidence", "a name", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_CONF) == 0 {
                let lvl = conf_of_name(v);
                if lvl < 0 {
                    config_bad(err, "min_confidence", "low, medium or high");
                    bad = true;
                } else { conf = lvl; }
            }
        } else if key == "exclude" {
            let v, ok = cfg_str(r, scratch, "exclude", "a list of rule IDs", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_EXCL) == 0 {
                for b in v { excl.push(b); }
            }
        } else if key == "include" {
            let v, ok = cfg_str(r, scratch, "include", "a list of rule IDs", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_INCL) == 0 {
                for b in v { incl.push(b); }
            }
        } else if key == "exclude_path" {
            let v, ok = cfg_str(r, scratch, "exclude_path",
                "a list of path parts", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_PATH) == 0 {
                for b in v { paths.push(b); }
            }
        } else if key == "policy" {
            let v, ok = cfg_str(r, scratch, "policy", "a path", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_POLICY) == 0 {
                for b in v { policy.push(b); }
            }
        } else if key == "advisories" {
            let v, ok = cfg_str(r, scratch, "advisories", "a path", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_ADV) == 0 {
                for b in v { adv.push(b); }
            }
        } else if key == "rules" {
            let v, ok = cfg_str(r, scratch, "rules", "a list of paths", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_RULES) == 0 {
                for b in v { rules.push(b); }
            }
        } else if key == "max_files" {
            let v, ok = cfg_num(r, "max_files", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_FILES) == 0 { files = v; }
        } else if key == "max_depth" {
            let v, ok = cfg_num(r, "max_depth", err);
            if !ok {
                bad = true;
            } else if (mask & CFG_DEPTH) == 0 { depth = v; }
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
    if excl.len > 0 && !config_ids(excl[..], "exclude", true, err) {
        return false;
    }
    if incl.len > 0 && !config_ids(incl[..], "include", false, err) {
        return false;
    }
    if paths.len > 0 { config_paths(paths[..]); }
    return true;
}
