// The custom rules: a caller adds rules of its own from a JSON file.
// Each rule matches one shape of token: an identifier, a string
// literal or a comment. The rules join the registry, so the filters,
// the suppressions and the exit code treat them like the built-in
// rules.
namespace sast;

import json;
import regex;

// The kinds of a custom rule.
const CR_IDENT: i64 = 1;
const CR_STRING: i64 = 2;
const CR_COMMENT: i64 = 3;
const CR_REGEX: i64 = 4;

// The most custom rules that one run may hold.
const MAX_CUSTOM: i64 = 1024;

// The compiled expressions of the regex rules, in the order of the
// rules. An array of compiled expressions takes appends and a walk, no
// index. An array of expressions holds no resize call, so the rules of a
// file that faults stay out of the run. The slot of an expression is
// the place of its rule in cr_kind.
var cr_regex: regex::Regex[>..] = [];

// The custom rules of the run. The bytes of the match text live in one
// buffer; the offset lists hold the range of each rule.
var cr_buf: u8[>..] = [];
var cr_kind: i64[>..] = [];
var cr_exact: bool[>..] = [];
var cr_text_at: i64[>..] = [];
var cr_text_end: i64[>..] = [];
var cr_rule: i64[>..] = [];

// The ID and the message of each custom rule, in buffers the registry
// can point at for the whole run.
var cr_id_buf: u8[>..] = [];
var cr_msg_buf: u8[>..] = [];

// cr_own copies a text into a run buffer and gives the slice.
fn cr_own(out: u8[>..]&, text: const u8[:]) -> const u8[:] {
    let at = out.len;
    for c in text { out.push(c); }
    return out[at..out.len];
}

// The count of the built-in rules. A reset cuts the registry back to
// it, so a second file replaces the first.
var cr_base: i64 = -1;

// custom_reset drops the custom rules and cuts the registry back to
// the built-in rows.
fn custom_reset() {
    reg_ensure();
    if cr_base < 0 { cr_base = reg_id_s.len; }
    custom_cut(cr_base, 0);
    cr_buf.resize(0, 0);
    cr_regex = [];
}

// custom_cut cuts the registry to reg_len rows and the custom rule
// lists to cr_len rules. custom_reset uses it for a fresh run and
// custom_undo uses it for a file that faults.
fn custom_cut(reg_len: i64, cr_len: i64) {
    if reg_id_s.len > reg_len {
        reg_id_s.resize(reg_len, "");
        reg_sev_s.resize(reg_len, 0);
        reg_conf_s.resize(reg_len, 0);
        reg_cwe_s.resize(reg_len, 0);
        reg_alias_s.resize(reg_len, "");
        reg_msg_s.resize(reg_len, "");
        reg_tier_s.resize(reg_len, TIER_DEFAULT);
    }
    cr_kind.resize(cr_len, 0);
    cr_exact.resize(cr_len, false);
    cr_text_at.resize(cr_len, 0);
    cr_text_end.resize(cr_len, 0);
    cr_rule.resize(cr_len, 0);
    // The byte buffers keep the bytes of a failed file. The registry
    // holds no slice into them any more, so no rule uses them.
}

// cr_push copies one text into the custom buffer and gives its range.
fn cr_push(text: const u8[:]) -> i64, i64 {
    let at = cr_buf.len;
    for b in text { cr_buf.push(b); }
    return at, cr_buf.len;
}

// cr_holds reports whether the word holds the text of the rule i.
// The word is the token, the text is what the rule looks for.
fn cr_holds(i: i64, word: const u8[:]) -> bool {
    let text = cr_buf[cr_text_at[i]..cr_text_end[i]];
    if cr_exact[i] { return text == word; }
    return has_word(word, text);
}

// read_custom reads a custom rule file. The file holds a list under the
// key rules. Each rule holds an id, a severity, a kind, a text and an
// optional exact flag and message. It gives false on a fault, with the
// message in err.
fn read_custom(text: const u8[:], err: u8[>..]&) -> bool {
    custom_reset();
    return read_custom_more(text, err);
}

// read_custom_more reads a custom rule file and adds its rules to the
// registry of the run. It keeps the rules that the earlier files
// added. A rule ID that the registry holds is a fault.
fn read_custom_more(text: const u8[:], err: u8[>..]&) -> bool {
    reg_ensure();
    if cr_base < 0 { cr_base = reg_id_s.len; }
    // The state before the file. A file that faults leaves the registry
    // as it was.
    let reg_len = reg_id_s.len;
    let cr_len = cr_kind.len;
    var scratch: u8[>..] = [];
    var r = json::reader(text);
    var bad: u8[>..] = [];
    // The expressions of this file. They join the run only when the
    // whole file reads, so a fault leaves no expression behind.
    var pending: regex::Regex[>..] = [];
    if json::peek(r) == 91 {
        read_custom_list(r, scratch, bad, pending);
    } else {
        json::each_member(r) { key =>
            if key == "rules" {
                read_custom_list(r, scratch, bad, pending);
            } else {
                json::skip(r);
            }
        };
    }
    if bad.len > 0 {
        custom_cut(reg_len, cr_len);
        for b in bad { err.push(b); }
        return false;
    }
    if !json::finish(r) {
        custom_cut(reg_len, cr_len);
        for b in json::message(r) { err.push(b); }
        return false;
    }
    for re in pending { cr_regex.push(copy(re)); }
    return true;
}

// read_custom_list reads the rules of a list.
fn read_custom_list(r: json::Reader&, scratch: u8[>..]&, bad: u8[>..]&,
                    pending: regex::Regex[>..]&) {
    json::each_element(r) {
        read_one_custom(r, scratch, bad, pending);
    };
}

// sev_of_name gives the severity of a name.
fn sev_of_name(name: const u8[:]) -> i64 {
    if name == "low" { return SEV_LOW; }
    if name == "medium" { return SEV_MEDIUM; }
    if name == "high" { return SEV_HIGH; }
    if name == "critical" { return SEV_CRITICAL; }
    return -1;
}

// kind_of_name gives the kind of a name.
fn kind_of_name(name: const u8[:]) -> i64 {
    if name == "ident" { return CR_IDENT; }
    if name == "string" { return CR_STRING; }
    if name == "comment" { return CR_COMMENT; }
    if name == "regex" { return CR_REGEX; }
    return -1;
}

// read_one_custom reads one rule of the list and appends it to the
// registry. Every string is copied at once, because a read string
// points into the text of the reader.
fn read_one_custom(r: json::Reader&, scratch: u8[>..]&, bad: u8[>..]&,
                   pending: regex::Regex[>..]&) {
    var id: u8[>..] = [];
    var sev_name: u8[>..] = [];
    var kind_name: u8[>..] = [];
    var match_text: u8[>..] = [];
    var msg: u8[>..] = [];
    var exact = false;
    json::each_member(r) { key =>
        if key == "id" {
            let s2 = json::read_string(r, scratch);
            for c in s2 { id.push(c); }
        } else if key == "severity" {
            let s2 = json::read_string(r, scratch);
            for c in s2 { sev_name.push(c); }
        } else if key == "kind" {
            let s2 = json::read_string(r, scratch);
            for c in s2 { kind_name.push(c); }
        } else if key == "text" {
            let s2 = json::read_string(r, scratch);
            for c in s2 { match_text.push(c); }
        } else if key == "message" {
            let s2 = json::read_string(r, scratch);
            for c in s2 { msg.push(c); }
        } else if key == "exact" {
            exact = json::read_bool(r);
        } else {
            json::skip(r);
        }
    };
    let sev = sev_of_name(sev_name[..]);
    let kind = kind_of_name(kind_name[..]);
    if id.len == 0 { format(bad, "a rule holds no id\n"); return; }
    if sev < 0 { format(bad, "the severity of ", id[..], " is not a name\n"); return; }
    if kind < 0 { format(bad, "the kind of ", id[..], " is not a name\n"); return; }
    if match_text.len == 0 { format(bad, "the rule ", id[..], " holds no text\n"); return; }
    if cr_kind.len >= MAX_CUSTOM {
        format(bad, "a run holds at most 1024 custom rules\n");
        return;
    }
    if reg_find(id[..]) >= 0 { format(bad, "the id ", id[..], " is already in the registry\n"); return; }
    // A regex rule compiles at load. An expression that does not parse,
    // or that holds an anchor, is a fault that names the rule.
    if kind == CR_REGEX {
        var rx_err: u8[>..] = [];
        let re = regex::compile(match_text[..], rx_err);
        if rx_err.len > 0 {
            format(bad, "the expression of ", id[..], " does not compile: ", rx_err[..], "\n");
            return;
        }
        pending.push(copy(re));
    }
    var message: u8[>..] = [];
    if msg.len > 0 { for c in msg { message.push(c); } }
    else { for c in "a custom rule matched" { message.push(c); } }
    let own_id = cr_own(cr_id_buf, id[..]);
    let own_msg = cr_own(cr_msg_buf, message[..]);
    reg_put(own_id, sev, CONF_HIGH, 0, "", own_msg);
    let a, b = cr_push(match_text[..]);
    cr_text_at.push(a);
    cr_text_end.push(b);
    cr_kind.push(kind);
    cr_exact.push(exact);
    cr_rule.push(reg_id_s.len - 1);
}

// The offsets of the newlines of the last file. The list gives the
// line of a byte offset without a walk over the bytes. The length of
// that file gives the end of its last line.
var nl_at: i64[>..] = [];
var nl_len: i64 = 0;

// nl_build fills the list of the newline offsets of the text.
fn nl_build(src: const u8[:]) {
    nl_at.resize(0, 0);
    nl_len = src.len;
    var i: i64 = 0;
    while i < src.len {
        if src[i] == 10 { nl_at.push(i); }
        i = i + 1;
    }
}

// nl_pos gives the line and the column of the byte at. The line counts
// from 1 and the column counts from 1.
fn nl_pos(at: i64) -> i64, i64 {
    var lo: i64 = 0;
    var hi: i64 = nl_at.len;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if nl_at[mid] < at { lo = mid + 1; } else { hi = mid; }
    }
    let line = lo + 1;
    var last: i64 = -1;
    if lo > 0 { last = nl_at[lo - 1]; }
    return line, at - last;
}

// nl_span gives the place of the first byte of the line and of the
// byte after its last byte. The line counts from 1. A line of 0 gives
// two zeros.
fn nl_span(line: i64) -> i64, i64 {
    if line <= 0 { return 0, 0; }
    var start = if line == 1 { 0 } else { nl_at[line - 2] + 1 };
    var end = nl_len;
    if line - 1 < nl_at.len { end = nl_at[line - 1]; }
    return start, end;
}

// run_custom applies every custom rule over the tokens of the file.
// It gives the count of the findings it added.
fn run_custom(src: const u8[:], file_idx: i64, out: Finding[>..]&) -> i64 {
    reg_ensure();
    var found: i64 = 0;
    // The identifiers, then the strings, then the comments. Each pass
    // binds its own text, so no binding crosses a scope depth.
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && cr_kind.len > 0 {
            let word = tok_of(src, i);
            var k: i64 = 0;
            while k < cr_kind.len {
                if cr_kind[k] == CR_IDENT && cr_holds(k, word) {
                    rep(out, cr_rule[k], file_idx, tk_line[i],
                        tok_col_of(src, tk_start[i]), reg_msg_s[cr_rule[k]]);
                    found = found + 1;
                }
                k = k + 1;
            }
        }
        i = i + 1;
    }
    i = 0;
    while i < tk_count {
        if tk_kind[i] == TK_STRING && cr_kind.len > 0 {
            let word = lit_body(tok_of(src, i));
            var k: i64 = 0;
            while k < cr_kind.len {
                if cr_kind[k] == CR_STRING && cr_holds(k, word) {
                    rep(out, cr_rule[k], file_idx, tk_line[i],
                        tok_col_of(src, tk_start[i]), reg_msg_s[cr_rule[k]]);
                    found = found + 1;
                }
                k = k + 1;
            }
        }
        i = i + 1;
    }
    i = 0;
    while i < tk_count {
        if tk_kind[i] == TK_COMMENT && cr_kind.len > 0 {
            let word = tok_of(src, i);
            var k: i64 = 0;
            while k < cr_kind.len {
                if cr_kind[k] == CR_COMMENT && cr_holds(k, word) {
                    rep(out, cr_rule[k], file_idx, tk_line[i],
                        tok_col_of(src, tk_start[i]), reg_msg_s[cr_rule[k]]);
                    found = found + 1;
                }
                k = k + 1;
            }
        }
        i = i + 1;
    }
    // The regex rules search the whole text of the file. The list of
    // the newline offsets gives the line of every match, so the bytes
    // of the file are walked once and not once per rule.
    nl_build(src);
    // The expressions come in the order of the regex rules. The ordinal
    // of an expression is its place among the regex rules.
    var ord: i64 = 0;
    for re in cr_regex {
        // The slot of the expression is the place of its rule in
        // cr_kind. The expressions come in the order of the rules.
        var slot: i64 = -1;
        var seen: i64 = 0;
        var k: i64 = 0;
        while k < cr_kind.len {
            if cr_kind[k] == CR_REGEX {
                if seen == ord { slot = k; break; }
                seen = seen + 1;
            }
            k = k + 1;
        }
        if slot < 0 { break; }
        var rx = re;
        regex::each_match(rx, src) { s, e =>
            // An empty match reports once, at the start of the file. Later
            // empty matches stay out, so a rule such as z* cannot flood.
            let later_empty = e == s && s > 0;
            if !later_empty && found < MAX_FILE_MATCHES {
                let line, col = nl_pos(s);
                rep(out, cr_rule[slot], file_idx, line, col,
                    reg_msg_s[cr_rule[slot]]);
                found = found + 1;
            }
        };
        ord = ord + 1;
    }
    return found;
}
