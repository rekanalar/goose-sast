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

// The suppressions of the file. Each range holds a first line, a last
// line, the rule it silences and the line of the comment that made
// it. A rule of -1 silences every rule. The used flag says that a
// finding fell in the range.
var supp_from: i64[>..] = [];
var supp_to: i64[>..] = [];
var supp_rule: i64[>..] = [];
var supp_at: i64[>..] = [];
var supp_used: bool[>..] = [];

// The ranges that a disable opened and no enable closed yet.
var supp_open_from: i64[>..] = [];
var supp_open_rule: i64[>..] = [];

// The rows of the report of the unused suppressions. Each row holds a
// path, a line and a rule ID. The path and the ID hold no byte outside
// printable ASCII.
var unused_text: u8[>..] = [];

// supp_close closes one open range at the line.
fn supp_close(at: i64, line: i64) {
    supp_push(supp_open_from[at], line, supp_open_rule[at], supp_open_from[at]);
    remove_at(supp_open_from, at);
    remove_at(supp_open_rule, at);
}

// supp_push adds one closed range. The at column holds the line of the
// comment that made the range.
fn supp_push(from: i64, to: i64, rule: i64, at: i64) {
    supp_from.push(from);
    supp_to.push(to);
    supp_rule.push(rule);
    supp_at.push(at);
    supp_used.push(false);
}

// supp_tok gives the next token of a list and the place after it. The
// tokens are separated by commas or spaces. An empty text means the
// list holds no more tokens.
fn supp_tok(text: const u8[:], at: i64) -> const u8[:], i64 {
    var s = at;
    while s < text.len && (text[s] == 32 || text[s] == 9 || text[s] == 44) { s = s + 1; }
    var e = s;
    while e < text.len && text[e] != 32 && text[e] != 9 && text[e] != 44 { e = e + 1; }
    if e == s { return "", at; }
    return text[s..e], e;
}

// supp_list_start gives the place where the ID list of a directive
// starts. It gives -1 when the directive names no list, so it covers
// every rule. The list follows a space, a colon, or both.
fn supp_list_start(text: const u8[:], at: i64) -> i64 {
    var s = at;
    while s < text.len && (text[s] == 32 || text[s] == 9) { s = s + 1; }
    if s >= text.len { return -1; }
    if text[s] == 58 { return s + 1; }
    if text[s] == 71 || text[s] == 66 { return s; }
    return -1;
}

// supp_inline_at gives the place after the word of a same-line
// directive. The colon forms of nosec are no same-line word, so a
// block directive never silences the line it sits on. It gives -1 when
// the comment holds no same-line word.
fn supp_inline_at(text: const u8[:]) -> i64 {
    var i: i64 = 0;
    while i < text.len {
        if i + 5 <= text.len && text[i..i + 5] == "nosec" {
            let e = i + 5;
            if !(e + 5 <= text.len && text[e..e + 5] == ":next")
                && !(e + 6 <= text.len && text[e..e + 6] == ":start")
                && !(e + 4 <= text.len && text[e..e + 4] == ":end") {
                return e;
            }
        } else if i + 4 <= text.len && text[i..i + 4] == "noqa" {
            return i + 4;
        } else if i + 9 <= text.len && text[i..i + 9] == "nosemgrep" {
            return i + 9;
        }
        i = i + 1;
    }
    return -1;
}

// supp_next_at gives the place after the word of a next-line
// directive. It gives -1 when the comment holds none.
fn supp_next_at(text: const u8[:]) -> i64 {
    var i: i64 = 0;
    while i < text.len {
        if i + 10 <= text.len && text[i..i + 10] == "nosec:next" { return i + 10; }
        if i + 28 <= text.len
            && text[i..i + 28] == "goose-sast:disable-next-line" {
            return i + 28;
        }
        i = i + 1;
    }
    return -1;
}

// supp_add adds the ranges of a directive that covers the line cover.
// A directive with no list covers every rule. A directive with a list
// covers the rules of the list. An ID that no rule carries covers
// nothing, so a typo never hides a finding.
fn supp_add(text: const u8[:], at: i64, line: i64, cover: i64) {
    let start = supp_list_start(text, at);
    if start < 0 {
        supp_push(cover, cover, -1, line);
        return;
    }
    var s = start;
    while s < text.len {
        let tok, nxt = supp_tok(text, s);
        if tok.len == 0 { break; }
        let idx = reg_find(tok);
        if idx >= 0 { supp_push(cover, cover, idx, line); }
        s = nxt;
    }
}

// suppress_ranges reads the suppression comments of the source. A
// comment with `nosec:start` or `goose-sast:disable` opens a range,
// and a comment with `nosec:end` or `goose-sast:enable` closes it. A
// comment with `nosec:next` covers the line below it. A comment with
// `nosec`, `noqa` or `nosemgrep` covers its own line. A range with no
// end reaches the end of the file.
fn suppress_ranges(src: const u8[:]) {
    supp_from.resize(0, 0);
    supp_to.resize(0, 0);
    supp_rule.resize(0, 0);
    supp_at.resize(0, 0);
    supp_used.resize(0, false);
    supp_open_from.resize(0, 0);
    supp_open_rule.resize(0, 0);
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_COMMENT {
            let text = tok_of(src, i);
            let line = tk_line[i];
            let next_at = supp_next_at(text);
            if next_at >= 0 {
                // Only a comment that stands alone covers the next line.
                if i == 0 || tk_line[i - 1] != line {
                    supp_add(text, next_at, line, line + 1);
                }
            } else if has_word(text, "nosec:start") || has_word(text, "goose-sast:disable") {
                // The IDs sit after the word, when the comment holds
                // any.
                var k: i64 = 0;
                var ids_at: i64 = -1;
                while k < text.len {
                    if k + 5 <= text.len && text[k..k + 5] == "start"
                        && has_word(text, "nosec:start") {
                        ids_at = k + 5;
                        break;
                    }
                    if k + 7 <= text.len && text[k..k + 7] == "disable"
                        && has_word(text, "goose-sast:disable") {
                        ids_at = k + 7;
                        break;
                    }
                    k = k + 1;
                }
                if ids_at < 0 || supp_read_ids(text, ids_at, line) == 0 {
                    supp_open_from.push(line);
                    supp_open_rule.push(-1);
                }
            } else if has_word(text, "nosec:end") || has_word(text, "goose-sast:enable") {
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
                            // A named enable closes named ranges; the
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
            // A same-line directive covers the line of the comment.
            let inline_at = supp_inline_at(text);
            if inline_at >= 0 {
                supp_add(text, inline_at, line, line);
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

// supp_read_ids reads the rule IDs of a block directive. The IDs sit
// after the word, separated by commas or spaces. An ID that no rule
// carries stays out. It gives -1 when the comment holds tokens but no
// known ID, so the caller opens no range. It gives 0 when no token
// follows the word, so the caller opens every rule.
fn supp_read_ids(text: const u8[:], at: i64, line: i64) -> i64 {
    var s = at;
    var read: i64 = 0;
    var tokens: i64 = 0;
    while s < text.len {
        let tok, nxt = supp_tok(text, s);
        if tok.len == 0 { break; }
        tokens = tokens + 1;
        let idx = reg_find(tok);
        if idx >= 0 {
            supp_open_from.push(line);
            supp_open_rule.push(idx);
            read = read + 1;
        }
        s = nxt;
    }
    if read == 0 && tokens > 0 { return -1; }
    return read;
}

// in_block reports whether the rule sits in a suppression of the line.
// A range with a rule of -1 silences every rule. The used flag of
// every range that covers the finding is set, so the report of the
// unused suppressions knows which ranges silenced a finding.
fn in_block(line: i64, rule_idx: i64, report: bool) -> bool {
    var hit = false;
    var i: i64 = 0;
    while i < supp_from.len {
        if line >= supp_from[i] && line <= supp_to[i]
            && (supp_rule[i] < 0 || supp_rule[i] == rule_idx) {
            supp_used[i] = true;
            hit = true;
            if !report { return true; }
        }
        i = i + 1;
    }
    return hit;
}

// unused_row appends one row of the unused report. The path and the
// ID hold no byte outside printable ASCII, so a hostile path cannot
// forge a row.
fn unused_row(path: const u8[:], line: i64, id: const u8[:]) {
    put_escaped(unused_text, path);
    format(unused_text, ":", line, ": unused suppression");
    if id.len > 0 {
        unused_text.push(32);
        unused_text.push(91);
        put_escaped(unused_text, id);
        unused_text.push(93);
    }
    unused_text.push(10);
}

// unused_report finds the suppressions of the file that silenced no
// finding. A directive with a list gives one row for each rule of the
// list that matched nothing. An ID that no rule carries gives no row.
fn unused_report(path: const u8[:]) {
    var i: i64 = 0;
    while i < supp_from.len {
        if !supp_used[i] {
            if supp_rule[i] < 0 { unused_row(path, supp_at[i], ""); }
            else { unused_row(path, supp_at[i], reg_id_s[supp_rule[i]]); }
        }
        i = i + 1;
    }
}

// keep reports whether a finding passes the options: the severity, the
// confidence, the profile, the include list and the exclude list.
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
    // The default profile leaves out the rules of the strict tier. The
    // include list turns the rule on again, because the user named it.
    var named = opt_holds(incl_at[..], incl_end[..], id);
    var m: i64 = 0;
    while m < incl_at.len && !named {
        let want = buf_opt_ids[incl_at[m]..incl_end[m]];
        if al.len > 0 && alias_holds(al, want) { named = true; }
        m = m + 1;
    }
    if o.profile == PROFILE_DEFAULT && reg_tier_s[rule_idx] == TIER_STRICT
        && !named {
        return false;
    }
    if incl_at.len > 0 && !named { return false; }
    return true;
}

// scan_text scans one file. The path is the name the findings carry.
// It appends the findings to out and gives the number of findings it
// kept. The tokens of the file replace the tokens of the last file.
fn scan_text(path: const u8[:], src: const u8[:], o: Options, out: Finding[>..]&) -> i64 {
    reg_ensure();
    let file_idx = add_path(path);
    // The hash of the path is the same for every finding of the file.
    let path_hash = fnv64(path);
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
    rule_shapes(src, file_idx, raw);
    rule_bounds(src, file_idx, raw);
    run_custom(src, file_idx, raw);
    var kept: i64 = 0;
    for f in raw {
        let id = reg_id_s[f.rule];
        let al = reg_alias_s[f.rule];
        if in_block(f.line, f.rule, o.report_unused) {
            continue;
        }
        if keep(o, f.rule, f.sev, f.conf) {
            // The count of the findings of a run is bounded. A file
            // that matches a rule on every line cannot fill the memory.
            if out.len >= MAX_FINDINGS {
                findings_hit_cap = true;
                break;
            }
            // The fingerprint of the finding: rule, path, the text of
            // its line. The line bytes come from the newline table.
            let lstart, lend = nl_span(f.line);
            let fat = buf_texts.len;
            fingerprint_hashes(rule_hash(f.rule), path_hash,
                               fnv64(src[lstart..lend]), buf_texts);
            var g = f;
            g.fp = fat;
            g.fp_end = buf_texts.len;
            out.push(g);
            kept = kept + 1;
        }
    }
    if o.report_unused { unused_report(path); }
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
                        // The default and the strict profiles leave out
                        // the test and the example directories that the
                        // walk finds. The match is exact and lower
                        // case. The target is never an entry of a
                        // listing, so a target named test is scanned.
                        if o.profile != PROFILE_ALL
                            && (name == "test" || name == "examples") {
                            dirs_left_out = dirs_left_out + 1;
                        } else {
                            q_add(path[..], depth + 1);
                        }
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

// dirs_left_out counts the directories that the profile left out of
// the walk. The count is a counter, and the walk never enters a
// left-out directory. scan_reset clears it.
var dirs_left_out: i64 = 0;

// scan_reset clears the list of the directories that the walk entered.
// A run over several trees calls it once, so a directory that two
// targets name is walked once.
fn scan_reset() {
    vis_reset();
    findings_reset();
    baseline_reset();
    findings_hit_cap = false;
    unused_text.resize(0, 0);
    dirs_left_out = 0;
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
