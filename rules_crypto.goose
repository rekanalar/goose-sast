// The crypto and import rules: the weak hash, the weak random, and the
// blocklist imports.
namespace sast;

// rule_weakhash runs G401: an identifier that names md5, sha1, md4 or
// ripemd160.
fn rule_weakhash(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT {
            let name = tok_of(src, i);
            if name == "md5" || name == "sha1" || name == "md4"
                || name == "ripemd160" || name == "Md5" || name == "Sha1" {
                rep(out, 13, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                    "a weak hash is in use");
            }
        }
        i = i + 1;
    }
}

// rule_weakrand runs G404: the non-crypto random calls of the standard
// library, and a constant-seeded rng literal.
fn rule_weakrand(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT {
            let name = tok_of(src, i);
            if name == "rand_u64" || name == "rand_int" || name == "rand_flt"
                || name == "shuffle" {
                rep(out, 14, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                    "a weak random source is in use");
            } else if name == "rng" && i + 1 < tk_count && tk_kind[i + 1] == TK_OTHER
                && tok_of(src, i + 1) == "{"
                && i + 2 < tk_count && tk_kind[i + 2] == TK_NUMBER {
                rep(out, 14, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                    "a weak random source is in use");
            }
        }
        i = i + 1;
    }
}

// import_target gives the package source of an import line. i sits on
// the import keyword; the target is the string literal after from.
fn import_target(src: const u8[:], i: i64) -> const u8[:] {
    var k = i + 1;
    while k < tk_count && tk_line[k] == tk_line[i] {
        if tok_of(src, k) == "from" && k + 1 < tk_count
            && tk_kind[k + 1] == TK_STRING {
            let lit = tok_of(src, k + 1);
            return lit[1..lit.len - 1];
        }
        if tk_line[k] != tk_line[i] { break; }
        k = k + 1;
    }
    return "";
}

// import_block_target gives the blocklist rule index of the target.
// It gives -1 when no row matches.
fn import_block_target(target: const u8[:]) -> i64 {
    var low: u8[>..] = [];
    lower_of(target, low);
    if has_word(low[..], "md5") { return 21; }
    if has_word(low[..], "des") { return 22; }
    if has_word(low[..], "rc4") { return 23; }
    if has_word(low[..], "cgi") { return 24; }
    if has_word(low[..], "sha1") { return 25; }
    if has_word(low[..], "md4") { return 26; }
    if has_word(low[..], "ripemd160") { return 27; }
    return -1;
}

// import_bandit_target gives the rule index of the bandit import rows.
// It gives -1 when no row matches.
fn import_bandit_target(target: const u8[:]) -> i64 {
    var low: u8[>..] = [];
    lower_of(target, low);
    if has_word(low[..], "telnet") { return 28; }
    if has_word(low[..], "ftp") { return 29; }
    if has_word(low[..], "pickle") { return 30; }
    if has_word(low[..], "process") { return 31; }
    if has_word(low[..], "xmlrpc") { return 38; }
    if has_word(low[..], "lxml") { return 37; }
    return -1;
}

// rule_blocklist runs G501 to G507 and B401 to B415: the import lines
// of the blocklist. Each import line reports at most one row; the gosec
// rows win over the bandit rows.
fn rule_blocklist(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "import" {
            let target = import_target(src, i);
            if target.len > 0 {
                let g = import_block_target(target);
                if g >= 0 {
                    rep(out, g, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                        reg_msg_s[g]);
                } else {
                    let b = import_bandit_target(target);
                    if b >= 0 {
                        rep(out, b, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]), reg_msg_s[b]);
                    }
                }
            }
        }
        i = i + 1;
    }
}
