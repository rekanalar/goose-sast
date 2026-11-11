// The scan: it runs every rule over one text or over a tree, drops the
// findings that the options or a suppression comment filter out, and
// sorts what is left by file, line and rule.
namespace sast;

import os;

// ends_with reports whether s ends with the suffix.
fn ends_with(s: const u8[:], suffix: const u8[:]) -> bool {
    if s.len < suffix.len { return false; }
    return s[s.len - suffix.len..s.len] == suffix;
}

// suppressed reports whether the line of the finding holds a suppression
// comment that names the rule or names none. The comment holds `nosec`,
// `noqa` or `nosemgrep`, then an optional list of rule IDs.
fn suppressed(src: const u8[:], line: i64, rule_id: const u8[:], alias: const u8[:]) -> bool {
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
    var kept: i64 = 0;
    for f in raw {
        let id = reg_id_s[f.rule];
        let al = reg_alias_s[f.rule];
        if suppressed(src, f.line, id, al) {
            continue;
        }
        if keep(o, f.rule, f.sev, f.conf) {
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

// scan_walk walks the queue breadth first. It reads each .goose file
// once, follows no link and stops at the depth bound. It counts the
// files it scanned in scanned and the entries it skipped in skipped.
fn scan_walk(o: Options, out: Finding[>..]&, scanned: i64&, skipped: i64&) {
    var head: i64 = 0;
    while head < q_at.len {
        let depth = q_depth[head];
        var dir: u8[>..] = [];
        for b in q_buf[q_at[head]..q_end[head]] { dir.push(b); }
        head = head + 1;
        if depth > o.max_depth { skipped = skipped + 1; continue; }
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
                    if is_dir(path[..]) {
                        q_add(path[..], depth + 1);
                    } else if ends_with(name, ".goose") {
                        var src: u8[>..] = [];
                        if scanned >= o.max_files || !read_file(path[..], src)
                            || src.len > o.max_file {
                            skipped = skipped + 1;
                        } else {
                            scanned = scanned + 1;
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
    var scanned: i64 = 0;
    var skipped: i64 = 0;
    q_at.resize(0, 0);
    q_end.resize(0, 0);
    q_depth.resize(0, 0);
    q_buf.resize(0, 0);
    q_add(dir, 0);
    scan_walk(o, out, scanned, skipped);
    sort_findings(out);
    return scanned, skipped;
}
