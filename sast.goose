// goose-sast - A security linter for Goose: source rules, dependency
// policy checks and advisory checks.
//
// The entry file holds the finding store, the options, the severity and
// confidence orders, and the rule registry. The rule matchers live in
// the rules_*.goose files. scan.goose runs the matchers over a file or
// a tree. format.goose prints the findings.
namespace sast;

import lex;
import rules_cred;
import rules_crypto;
import rules_inject;
import rules_go;
import scan;
import format;

// The severity order. A finding with a lower severity than the option
// does not print and does not set the exit code.
const SEV_LOW: i64 = 1;
const SEV_MEDIUM: i64 = 2;
const SEV_HIGH: i64 = 3;
const SEV_CRITICAL: i64 = 4;

// The confidence order.
const CONF_LOW: i64 = 1;
const CONF_MEDIUM: i64 = 2;
const CONF_HIGH: i64 = 3;

// The bounds of one run. A bound reached is a count for the walk. For
// the two JSON files of the dependency checks it is a fault.
const MAX_FILE: i64 = 16777216;
const MAX_FILES: i64 = 4096;
const MAX_DEPTH: i64 = 64;
const MAX_FINDINGS: i64 = 65536;

// Finding is one reported defect. Every field is fixed size, so a list
// of findings is a plain array the caller owns.
struct Finding {
    rule: i64,      // the index in the rule registry
    sev: i64,
    conf: i64,
    cwe: i64,
    file: i64,      // the index in the path table
    line: i64,
    col: i64,
    msg: i64,       // the offset in the message buffer
    msg_end: i64,
}

// Options holds the filters and the bounds of one run. The three ID
// lists live in the globals below, because a struct holds one growable
// field only. opt_reset() empties them before a run sets them.
struct Options {
    min_severity: i64,
    min_confidence: i64,
    max_file: i64,
    max_files: i64,
    max_depth: i64,
}

// The ID lists of the run: rules to leave out, rules to keep, and path
// parts to skip in the walk. The bytes live in one buffer; the two
// offset lists of each list hold the range of one entry.
var buf_opt_ids: u8[>..] = [];
var excl_at: i64[>..] = [];
var excl_end: i64[>..] = [];
var incl_at: i64[>..] = [];
var incl_end: i64[>..] = [];
var paths_at: i64[>..] = [];
var paths_end: i64[>..] = [];

// default_options gives the options of a plain run. It resets the
// lists, because the globals of one run carry them.
fn default_options() -> Options {
    opt_reset();
    return Options {
        min_severity: SEV_LOW,
        min_confidence: CONF_LOW,
        max_file: MAX_FILE, max_files: MAX_FILES, max_depth: MAX_DEPTH,
    };
}

// opt_reset empties the three lists.
fn opt_reset() {
    buf_opt_ids.resize(0, 0);
    excl_at.resize(0, 0);
    excl_end.resize(0, 0);
    incl_at.resize(0, 0);
    incl_end.resize(0, 0);
    paths_at.resize(0, 0);
    paths_end.resize(0, 0);
}

// opt_push copies one ID or path part into the option buffer and holds
// its range in the offsets. A copy is the point: the caller's text may
// not outlive the run.
fn opt_push(at: i64[>..]&, end: i64[>..]&, s: const u8[:]) {
    at.push(buf_opt_ids.len);
    for b in s { buf_opt_ids.push(b); }
    end.push(buf_opt_ids.len);
}

// opt_exclude adds one rule ID to the exclude list.
fn opt_exclude(id: const u8[:]) { opt_push(excl_at, excl_end, id); }

// opt_include adds one rule ID to the include list.
fn opt_include(id: const u8[:]) { opt_push(incl_at, incl_end, id); }

// opt_skip_path adds one path part to the walk skip list.
fn opt_skip_path(part: const u8[:]) { opt_push(paths_at, paths_end, part); }

// opt_holds reports whether the offset list holds the ID.
fn opt_holds(at: const i64[:], end: const i64[:], id: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < at.len {
        if buf_opt_ids[at[i]..end[i]] == id { return true; }
        i = i + 1;
    }
    return false;
}

// The message and path buffers of the current run. One run holds them.
// findings_reset() empties the store before a run.
var buf_texts: u8[>..] = [];
var buf_paths: u8[>..] = [];
var buf_path_off: i64[>..] = [];

// findings_reset empties the buffers of the store.
fn findings_reset() {
    buf_texts.resize(0, 0);
    buf_paths.resize(0, 0);
    buf_path_off.resize(0, 0);
}

// add_path interns a path and gives its index.
fn add_path(path: const u8[:]) -> i64 {
    let idx = buf_path_off.len;
    buf_path_off.push(buf_paths.len);
    for b in path { buf_paths.push(b); }
    return idx;
}

// path_of gives the path of the index i as a slice.
fn path_of(i: i64) -> const u8[:] {
    let at = buf_path_off[i];
    var end = buf_paths.len;
    if i + 1 < buf_path_off.len { end = buf_path_off[i + 1]; }
    return buf_paths[at..end];
}

// msg_of gives the message of the finding as a slice.
fn msg_of(f: Finding) -> const u8[:] {
    return buf_texts[f.msg..f.msg_end];
}

// The rule registry. The rows hold the ID, the severity, the
// confidence, the CWE number, the alias IDs and the message. The
// registry loads once into growable arrays.
var reg_loaded = false;
var reg_id_s: const u8[:][>..] = [];
var reg_sev_s: i64[>..] = [];
var reg_conf_s: i64[>..] = [];
var reg_cwe_s: i64[>..] = [];
var reg_alias_s: const u8[:][>..] = [];
var reg_msg_s: const u8[:][>..] = [];

// reg_ensure loads the registry once.
fn reg_ensure() {
    if reg_loaded { return; }
    reg_loaded = true;
    // id, sev, conf, cwe, alias, message
    reg_put("G101", SEV_HIGH, CONF_LOW, 798, "B105,B106,B107", "a credential may be hardcoded");
    reg_put("G102", SEV_MEDIUM, CONF_HIGH, 605, "B104", "the program binds to all interfaces");
    reg_put("G109", SEV_HIGH, CONF_MEDIUM, 786, "G115", "a narrowing cast may lose bits");
    reg_put("G116", SEV_HIGH, CONF_MEDIUM, 1234, "B613", "the source holds bidirectional control characters");
    reg_put("G201", SEV_MEDIUM, CONF_HIGH, 89, "", "a SQL query is built with a format call");
    reg_put("G202", SEV_MEDIUM, CONF_HIGH, 89, "B608", "a SQL query is built by concatenation");
    reg_put("G203", SEV_MEDIUM, CONF_LOW, 79, "", "HTML is built from a variable");
    reg_put("G204", SEV_MEDIUM, CONF_HIGH, 78, "", "a command is built from a variable");
    reg_put("G301", SEV_MEDIUM, CONF_HIGH, 732, "", "a directory gets wide permissions");
    reg_put("G302", SEV_MEDIUM, CONF_HIGH, 732, "B103", "file permissions are too wide");
    reg_put("G303", SEV_MEDIUM, CONF_HIGH, 377, "B108", "a temp path is predictable");
    reg_put("G304", SEV_MEDIUM, CONF_HIGH, 22, "", "a file path comes from a variable");
    reg_put("G306", SEV_MEDIUM, CONF_HIGH, 732, "", "a write gets wide permissions");
    reg_put("G401", SEV_MEDIUM, CONF_HIGH, 327, "B324", "a weak hash is in use");
    reg_put("G404", SEV_HIGH, CONF_MEDIUM, 338, "B311", "a weak random source is in use");
    reg_put("G111", SEV_MEDIUM, CONF_MEDIUM, 22, "", "the path is the root directory");
    reg_put("B101", SEV_LOW, CONF_HIGH, 612, "", "an assert may be removed in a release build");
    reg_put("B110", SEV_LOW, CONF_HIGH, 703, "B112", "a catch body holds nothing");
    reg_put("B113", SEV_MEDIUM, CONF_LOW, 1088, "", "a wait takes no time limit");
    reg_put("B607", SEV_LOW, CONF_HIGH, 114, "", "a command holds a partial path");
    reg_put("B609", SEV_HIGH, CONF_MEDIUM, 78, "", "a wildcard may expand in a command");
    reg_put("G501", SEV_MEDIUM, CONF_HIGH, 327, "", "an import of md5 is in use");
    reg_put("G502", SEV_MEDIUM, CONF_HIGH, 327, "", "an import of des is in use");
    reg_put("G503", SEV_MEDIUM, CONF_HIGH, 327, "", "an import of rc4 is in use");
    reg_put("G504", SEV_MEDIUM, CONF_HIGH, 386, "", "an import of cgi is in use");
    reg_put("G505", SEV_MEDIUM, CONF_HIGH, 327, "", "an import of sha1 is in use");
    reg_put("G506", SEV_MEDIUM, CONF_HIGH, 328, "", "an import of md4 is in use");
    reg_put("G507", SEV_MEDIUM, CONF_HIGH, 328, "", "an import of ripemd160 is in use");
    reg_put("B401", SEV_HIGH, CONF_HIGH, 319, "", "an import of telnet is in use");
    reg_put("B402", SEV_HIGH, CONF_HIGH, 319, "", "an import of ftp is in use");
    reg_put("B403", SEV_LOW, CONF_HIGH, 502, "", "an import of pickle is in use");
    reg_put("B404", SEV_LOW, CONF_HIGH, 78, "", "an import of a process package is in use");
    reg_put("B405", SEV_LOW, CONF_HIGH, 20, "", "an import of xml is in use");
    reg_put("B406", SEV_LOW, CONF_HIGH, 20, "", "an import of a sax xml reader is in use");
    reg_put("B407", SEV_LOW, CONF_HIGH, 20, "", "an import of a dom xml builder is in use");
    reg_put("B408", SEV_LOW, CONF_HIGH, 20, "", "an import of a minidom reader is in use");
    reg_put("B409", SEV_LOW, CONF_HIGH, 20, "", "an import of a pulldom reader is in use");
    reg_put("B410", SEV_LOW, CONF_HIGH, 382, "", "an import of lxml is in use");
    reg_put("B411", SEV_HIGH, CONF_HIGH, 20, "", "an import of xmlrpc is in use");
    reg_put("B412", SEV_HIGH, CONF_HIGH, 386, "", "an import of a cgi handler is in use");
    reg_put("B413", SEV_HIGH, CONF_HIGH, 327, "", "an import of a crypto cipher library is in use");
    reg_put("B414", SEV_LOW, CONF_HIGH, 327, "", "an import of a cryptography module is in use");
    reg_put("G103", SEV_LOW, CONF_HIGH, 242, "", "an extern function calls code outside the type checker");
    reg_put("G117", SEV_MEDIUM, CONF_MEDIUM, 499, "", "a secret-named value goes into a JSON writer");
    reg_put("B415", SEV_HIGH, CONF_HIGH, 502, "", "an import of a web application bridge is in use");
}

// reg_put appends one rule row.
fn reg_put(id: const u8[:], sev: i64, conf: i64, cwe: i64,
           alias: const u8[:], msg: const u8[:]) {
    reg_id_s.push(id);
    reg_sev_s.push(sev);
    reg_conf_s.push(conf);
    reg_cwe_s.push(cwe);
    reg_alias_s.push(alias);
    reg_msg_s.push(msg);
}

// reg_find gives the index of the ID s, with aliases resolved. It gives
// -1 when no rule carries the ID.
fn reg_find(s: const u8[:]) -> i64 {
    reg_ensure();
    var i: i64 = 0;
    while i < reg_id_s.len {
        if reg_id_s[i] == s { return i; }
        // The alias field holds IDs separated by commas.
        let al = reg_alias_s[i];
        if al.len > 0 && alias_holds(al, s) { return i; }
        i = i + 1;
    }
    return -1;
}

// alias_holds reports whether the alias field holds the ID.
fn alias_holds(al: const u8[:], s: const u8[:]) -> bool {
    var at: i64 = 0;
    while at <= al.len {
        var e = at;
        while e < al.len && al[e] != 44 { e = e + 1; }
        if e - at == s.len && al[at..e] == s { return true; }
        if e >= al.len { return false; }
        at = e + 1;
    }
    return false;
}

// rule_count gives the count of rules in the registry.
fn rule_count() -> i64 {
    reg_ensure();
    return reg_id_s.len;
}

// list_rules writes one line per rule: the ID, the severity, the
// confidence, the CWE number, the alias and the message.
fn list_rules(out: u8[>..]&) {
    reg_ensure();
    var i: i64 = 0;
    while i < reg_id_s.len {
        for b in reg_id_s[i] { out.push(b); }
        format(out, " sev=", reg_sev_s[i], " conf=", reg_conf_s[i],
               " cwe=", reg_cwe_s[i]);
        if reg_alias_s[i].len > 0 {
            format(out, " alias=", reg_alias_s[i]);
        }
        format(out, "  ", reg_msg_s[i], "\n");
        i = i + 1;
    }
}
