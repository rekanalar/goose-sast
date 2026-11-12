// The scan: it runs every rule over one text or over a tree, drops the
// findings that the options or a suppression comment filter out, and
// sorts what is left by file, line and rule.
namespace sast;

import os;
import std;

// ends_with reports whether s ends with the suffix.
fn ends_with(s: const u8[:], suffix: const u8[:]) -> bool {
    if s.len < suffix.len { return false; }
    return s[s.len - suffix.len..s.len] == suffix;
}

// The flag that says that the run reached the bound of the findings.
var findings_hit_cap = false;

// The block suppressions of the file. Each range holds a first line, a
// last line and the rule it silences. A rule of -1 silences every rule.
var supp_from: i64[>..] = [];
var supp_to: i64[>..] = [];
var supp_rule: i64[>..] = [];

// The ranges that a disable opened and no enable closed yet.
var supp_open_from: i64[>..] = [];
var supp_open_rule: i64[>..] = [];

// supp_close closes one open range at the line.
fn supp_close(at: i64, line: i64) {
    supp_from.push(supp_open_from[at]);
    supp_to.push(line);
    supp_rule.push(supp_open_rule[at]);
    remove_at(supp_open_from, at);
    remove_at(supp_open_rule, at);
}

// supp_read_ids reads the rule IDs of a directive. The IDs sit after
// the word, separated by commas or spaces. An ID that no rule carries
// stays out. It gives -1 when the comment holds tokens but no known
// ID, so the caller opens no range. It gives 0 when no token follows
// the word, so the caller opens every rule.
fn supp_read_ids(text: const u8[:], at: i64, line: i64) -> i64 {
    var s = at;
    var read: i64 = 0;
    var tokens: i64 = 0;
    while s < text.len {
        while s < text.len && (text[s] == 32 || text[s] == 44) { s = s + 1; }
        var e = s;
        while e < text.len && text[e] != 32 && text[e] != 44 { e = e + 1; }
        if e > s {
            tokens = tokens + 1;
            let idx = reg_find(text[s..e]);
            if idx >= 0 {
                supp_open_from.push(line);
                supp_open_rule.push(idx);
                read = read + 1;
            }
        }
        s = e;
    }
    if read == 0 && tokens > 0 { return -1; }
    return read;
}

// suppress_ranges reads the block suppression comments of the source.
// A comment with `nosec:start` or `goose-sast:disable` opens a range,
// and a comment with `nosec:end` or `goose-sast:enable` closes it. A
// directive may name rules, and then the range silences those rules
// only. A range with no end reaches the end of the file.
fn suppress_ranges(src: const u8[:]) {
    supp_from.resize(0, 0);
    supp_to.resize(0, 0);
    supp_rule.resize(0, 0);
    supp_open_from.resize(0, 0);
    supp_open_rule.resize(0, 0);
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_COMMENT {
            let text = tok_of(src, i);
            let line = tk_line[i];
            var all_open = false;
            var all_close = false;
            var ids_at: i64 = -1;
            if has_word(text, "nosec:start") || has_word(text, "goose-sast:disable") {
                // The IDs sit after the word, when the comment holds
                // any.
                var k: i64 = 0;
                while k < text.len {
                    if k + 5 <= text.len && text[k..k + 5] == "start"
                        && has_word(text, "nosec:start") {
                        ids_at = k + 5;
                        all_open = true;
                        break;
                    }
                    if k + 7 <= text.len && text[k..k + 7] == "disable"
                        && has_word(text, "goose-sast:disable") {
                        ids_at = k + 7;
                        all_open = true;
                        break;
                    }
                    k = k + 1;
                }
            } else if has_word(text, "nosec:end") || has_word(text, "goose-sast:enable") {
                all_close = true;
            }
            if all_open {
                // A range with no list silences every rule. A list of
                // unknown IDs gives -1 and silences nothing.
                if ids_at < 0 || supp_read_ids(text, ids_at, line) == 0 {
                    supp_open_from.push(line);
                    supp_open_rule.push(-1);
                }
            } else if all_close {
                // An enable with a list closes the ranges of those
                // rules; an enable with no list closes every range.
                var k: i64 = 0;
                while k < supp_open_from.len {
                    if has_word(text, "enable") {
                        // The IDs after the word, if any.
                        var m: i64 = 0;
                        var named = false;
                        while m + 6 <= text.len {
                            if text[m..m + 6] == "enable" {
                                m = m + 6;
                                break;
                            }
                            m = m + 1;
                        }
                        while m < text.len && (text[m] == 32 || text[m] == 58) { m = m + 1; }
                        if m < text.len {
                            let rid = supp_open_rule[k];
                            // An all-rule range closes on any named
                            // enable only when the list holds it? No:
                            // a named enable closes named ranges; the
                            // all-rule range stays open.
                            if rid < 0 { k = k + 1; continue; }
                            let want = reg_id_s[rid];
                            var e = m;
                            var held = false;
                            while e < text.len {
                                while e < text.len && (text[e] == 32 || text[e] == 44) { e = e + 1; }
                                var f = e;
                                while f < text.len && text[f] != 32 && text[f] != 44 { f = f + 1; }
                                if f > e && text[e..f] == want { held = true; break; }
                                e = f;
                            }
                            if !held { k = k + 1; continue; }
                            named = true;
                        }
                    }
                    supp_close(k, line);
                    if !has_word(text, "enable") { break; }
                }
            }
        }
        i = i + 1;
    }
    // A range with no end reaches the end of the file.
    var k: i64 = 0;
    var last: i64 = 0;
    if tk_count > 0 { last = tk_line[tk_count - 1]; }
    while k < supp_open_from.len {
        supp_close(k, last);
    }
}

// in_block reports whether the rule sits in a block suppression of the
// line. A range with a rule of -1 silences every rule.
fn in_block(line: i64, rule_idx: i64) -> bool {
    var i: i64 = 0;
    while i < supp_from.len {
        if line >= supp_from[i] && line <= supp_to[i]
            && (supp_rule[i] < 0 || supp_rule[i] == rule_idx) {
            return true;
        }
        i = i + 1;
    }
    return false;
}

// suppressed reports whether the line of the finding holds a suppression
// comment that names the rule or names none. The comment holds `nosec`,
// `noqa` or `nosemgrep`, then an optional list of rule IDs. A block
// suppression covers the line too.
fn suppressed(src: const u8[:], line: i64, rule_id: const u8[:], alias: const u8[:], rule_idx: i64) -> bool {
    if in_block(line, rule_idx) { return true; }
    let c = tok_line_comment(line);
    if c < 0 { return false; }
    let text = tok_of(src, c);
    var at = -1;
    var i: i64 = 0;
    while i + 5 <= text.len {
        if text[i..i + 5] == "nosec" { at = i + 5; break; }
        if i + 4 <= text.len && text[i..i + 4] == "noqa" { at = i + 4; break; }
        if i + 9 <= text.len && text[i..i + 9] == "nosemgrep" { at = i + 9; break; }
        i = i + 1;
    }
    if at < 0 { return false; }
    // A comment with no list suppresses every rule on the line.
    var k = at;
    while k < text.len && (text[k] == 32 || text[k] == 9) { k = k + 1; }
    if k >= text.len || text[k] != 71 && text[k] != 66 && text[k] != 58 { return true; }
    // A list: IDs separated by commas or spaces.
    var s = k;
    if text[s] == 58 { s = s + 1; }
    while s < text.len {
        while s < text.len && (text[s] == 32 || text[s] == 44) { s = s + 1; }
        var e = s;
        while e < text.len && text[e] != 32 && text[e] != 44 { e = e + 1; }
        if e > s {
            let id = text[s..e];
            if id == rule_id { return true; }
            if alias.len > 0 && alias_holds(alias, id) { return true; }
        }
        s = e;
    }
    return false;
}

// keep reports whether a finding passes the options: the severity, the
// confidence, the include list and the exclude list.
fn keep(o: Options, rule_idx: i64, sev: i64, conf: i64) -> bool {
    if sev < o.min_severity { return false; }
    if conf < o.min_confidence { return false; }
    reg_ensure();
    let id = reg_id_s[rule_idx];
    if opt_holds(excl_at[..], excl_end[..], id) { return false; }
    // An alias in the exclude list drops the rule too.
    let al = reg_alias_s[rule_idx];
    var j: i64 = 0;
    while j < excl_at.len {
        let got = buf_opt_ids[excl_at[j]..excl_end[j]];
        if al.len > 0 && alias_holds(al, got) { return false; }
        j = j + 1;
    }
    if incl_at.len > 0 {
        var found = opt_holds(incl_at[..], incl_end[..], id);
        var m: i64 = 0;
        while m < incl_at.len && !found {
            let want = buf_opt_ids[incl_at[m]..incl_end[m]];
            if al.len > 0 && alias_holds(al, want) { found = true; }
            m = m + 1;
        }
        if !found { return false; }
    }
    return true;
}

// scan_text scans one file. The path is the name the findings carry.
// It appends the findings to out and gives the number of findings it
// kept. The tokens of the file replace the tokens of the last file.
fn scan_text(path: const u8[:], src: const u8[:], o: Options, out: Finding[>..]&) -> i64 {
    reg_ensure();
    let file_idx = add_path(path);
    tokenize(src);
    suppress_ranges(src);
    var raw: Finding[>..] = [];
    rule_cred(src, file_idx, raw);
    rule_bind(src, file_idx, raw);
    rule_paths(src, file_idx, raw);
    rule_modes(src, file_idx, raw);
    rule_weakhash(src, file_idx, raw);
    rule_weakrand(src, file_idx, raw);
    rule_blocklist(src, file_idx, raw);
    rule_sql(src, file_idx, raw);
    rule_html(src, file_idx, raw);
    rule_proc(src, file_idx, raw);
    rule_wildcard(src, file_idx, raw);
    rule_cast(src, file_idx, raw);
    rule_bidi(src, file_idx, raw);
    rule_assert(path, src, file_idx, raw);
    rule_emptycatch(src, file_idx, raw);
    rule_timeout(src, file_idx, raw);
    rule_extern(src, file_idx, raw);
    rule_secretjson(src, file_idx, raw);
    rule_taint(src, file_idx, raw);
    rule_dropped(src, file_idx, raw);
    run_custom(src, file_idx, raw);
    var kept: i64 = 0;
    for f in raw {
        let id = reg_id_s[f.rule];
        let al = reg_alias_s[f.rule];
        if suppressed(src, f.line, id, al, f.rule) {
            continue;
        }
        if keep(o, f.rule, f.sev, f.conf) {
            // The count of the findings of a run is bounded. A file
            // that matches a rule on every line cannot fill the memory.
            if out.len >= MAX_FINDINGS {
                findings_hit_cap = true;
                break;
            }
            out.push(f);
            kept = kept + 1;
        }
    }
    return kept;
}

// sort_findings orders the findings by file, line, column and rule.
fn sort_findings(fs: Finding[>..]&) {
    sort(fs[..]) { a, b =>
        if a.file != b.file { a.file < b.file }
        else if a.line != b.line { a.line < b.line }
        else if a.col != b.col { a.col < b.col }
        else { a.rule < b.rule }
    };
}

// skip_part reports whether a path part sits on the skip list.
fn skip_part(name: const u8[:]) -> bool {
    return opt_holds(paths_at[..], paths_end[..], name);
}

// The queue of directories the walk has still to read. One entry holds
// the path bytes in q_buf, the range in q_at and q_end, and the depth.
var q_buf: u8[>..] = [];
var q_at: i64[>..] = [];
var q_end: i64[>..] = [];
var q_depth: i64[>..] = [];

// q_add appends one directory to the queue.
fn q_add(path: const u8[:], depth: i64) {
    q_at.push(q_buf.len);
    for b in path { q_buf.push(b); }
    q_end.push(q_buf.len);
    q_depth.push(depth);
}

// The directories the walk entered, as byte paths. A directory the
// list holds is a cycle, and the walk skips it.
var vis_buf: u8[>..] = [];
var vis_at: i64[>..] = [];
var vis_end: i64[>..] = [];

// vis_reset empties the visited list.
fn vis_reset() {
    vis_buf.resize(0, 0);
    vis_at.resize(0, 0);
    vis_end.resize(0, 0);
}

// vis_seen reports whether the walk already entered the path.
fn vis_seen(path: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < vis_at.len {
        if vis_buf[vis_at[i]..vis_end[i]] == path { return true; }
        i = i + 1;
    }
    return false;
}

// vis_put records that the walk entered the path.
fn vis_put(path: const u8[:]) {
    vis_at.push(vis_buf.len);
    for b in path { vis_buf.push(b); }
    vis_end.push(vis_buf.len);
}

// scan_walk walks the queue breadth first. It reads each .goose file
// once, follows no link and stops at the depth bound. It counts the
// files it scanned in scanned and the entries it skipped in skipped.
fn scan_walk(o: Options, out: Finding[>..]&, scanned: i64&, skipped: i64&,
             budget: i64&) {
    var head: i64 = 0;
    while head < q_at.len {
        let depth = q_depth[head];
        var dir: u8[>..] = [];
        for b in q_buf[q_at[head]..q_end[head]] { dir.push(b); }
        head = head + 1;
        if depth > o.max_depth { skipped = skipped + 1; continue; }
        // A directory the walk entered twice is a cycle.
        if vis_seen(dir[..]) { skipped = skipped + 1; continue; }
        vis_put(dir[..]);
        var listing: u8[>..] = [];
        if !list_dir(dir[..], listing) { skipped = skipped + 1; continue; }
        var start: i64 = 0;
        var i: i64 = 0;
        while i < listing.len {
            if listing[i] == 10 {
                let name = listing[start..i];
                start = i + 1;
                if name.len > 0 && !skip_part(name) {
                    var path: u8[>..] = [];
                    for b in dir { path.push(b); }
                    if dir.len > 0 && dir[dir.len - 1] != 47 { path.push(47); }
                    for b in name { path.push(b); }
                    // A link stays out of the walk, whatever it points
                    // at. A loop of links cannot make the walk read
                    // one file twice.
                    if path_is_link(path[..]) {
                        skipped = skipped + 1;
                    } else if is_dir(path[..]) {
                        q_add(path[..], depth + 1);
                    } else if ends_with(name, ".goose") {
                        var src: u8[>..] = [];
                        if budget <= 0
                            || !read_bounded(path[..], o.max_file, src) {
                            skipped = skipped + 1;
                        } else {
                            scanned = scanned + 1;
                            budget = budget - 1;
                            scan_text(path[..], src[..], o, out);
                        }
                    }
                }
            }
            i = i + 1;
        }
    }
}

// scan_dir scans every .goose file under the directory. It gives the
// number of files scanned. The skipped count is the second result.
fn scan_dir(dir: const u8[:], o: Options, out: Finding[>..]&) -> i64, i64 {
    scan_reset();
    var budget = o.max_files;
    let scanned, skipped = scan_dir_budget(dir, o, out, budget);
    sort_findings(out);
    return scanned, skipped;
}

// scan_reset clears the list of the directories that the walk entered.
// A run over several trees calls it once, so a directory that two
// targets name is walked once.
fn scan_reset() {
    vis_reset();
    findings_reset();
    findings_hit_cap = false;
}

// scan_dir_budget scans every .goose file under the directory. The
// budget holds the files that the run may still read. A run over
// several trees shares one budget, so the file count bound covers the
// whole run. It gives the number of files scanned. The skipped count
// is the second result. The function does not sort the findings and
// does not clear the list of the walked directories.
fn scan_dir_budget(dir: const u8[:], o: Options, out: Finding[>..]&,
                   budget: i64&) -> i64, i64 {
    var scanned: i64 = 0;
    var skipped: i64 = 0;
    q_at.resize(0, 0);
    q_end.resize(0, 0);
    q_depth.resize(0, 0);
    q_buf.resize(0, 0);
    q_add(dir, 0);
    scan_walk(o, out, scanned, skipped, budget);
    return scanned, skipped;
}
