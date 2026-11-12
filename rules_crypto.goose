// The crypto and import rules: the weak hash, the weak random, and the
// blocklist imports.
namespace sast;

// is_call reports whether the token i is a call: the next token is an
// open bracket and the token before is not the fn keyword. A function
// that carries the name is no call, so a definition does not report.
fn is_call(src: const u8[:], i: i64) -> bool {
    if i + 1 >= tk_count { return false; }
    if tk_kind[i + 1] != TK_OTHER || tok_of(src, i + 1) != "(" { return false; }
    if i > 0 && tk_kind[i - 1] == TK_IDENT && tok_of(src, i - 1) == "fn" {
        return false;
    }
    return true;
}

// The imported modules of the file. Each entry holds the name of the
// import and the path it came from. The bytes of both live in one
// buffer.
var imp_name_buf: u8[>..] = [];
var imp_path_buf: u8[>..] = [];
var imp_name_at: i64[>..] = [];
var imp_name_end: i64[>..] = [];
var imp_path_at: i64[>..] = [];
var imp_path_end: i64[>..] = [];

// read_imports reads the import lines of the source. Each import line
// holds the bound name, the word from and a string with the source.
fn read_imports(src: const u8[:]) {
    imp_reset();
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "import" {
            // The bound name sits after the word import.
            var k = i + 1;
            while k < tk_count && tk_line[k] == tk_line[i]
                && (tk_kind[k] != TK_IDENT || tok_of(src, k) == "from") {
                k = k + 1;
            }
            if k < tk_count && tk_kind[k] == TK_IDENT && tk_line[k] == tk_line[i] {
                let name = tok_of(src, k);
                let target = import_target(src, i);
                if target.len > 0 { imp_add(name, target); }
            }
        }
        i = i + 1;
    }
}

// imp_reset empties the import table.
fn imp_reset() {
    imp_name_buf.resize(0, 0);
    imp_path_buf.resize(0, 0);
    imp_name_at.resize(0, 0);
    imp_name_end.resize(0, 0);
    imp_path_at.resize(0, 0);
    imp_path_end.resize(0, 0);
}

// imp_add records one imported module.
fn imp_add(name: const u8[:], path: const u8[:]) {
    var at = imp_name_buf.len;
    for b in name { imp_name_buf.push(b); }
    imp_name_at.push(at);
    imp_name_end.push(imp_name_buf.len);
    at = imp_path_buf.len;
    for b in path { imp_path_buf.push(b); }
    imp_path_at.push(at);
    imp_path_end.push(imp_path_buf.len);
}

// imp_name gives the name of the import i.
fn imp_name(i: i64) -> const u8[:] {
    return imp_name_buf[imp_name_at[i]..imp_name_end[i]];
}

// imp_path gives the path of the import i.
fn imp_path(i: i64) -> const u8[:] {
    return imp_path_buf[imp_path_at[i]..imp_path_end[i]];
}

// imp_find gives the import of the name, or -1 when the file imports
// no such name.
fn imp_find(name: const u8[:]) -> i64 {
    var i: i64 = 0;
    while i < imp_name_at.len {
        if imp_name(i) == name { return i; }
        i = i + 1;
    }
    return -1;
}

// path_names reports whether the path of an import holds the word.
fn path_names(path: const u8[:], word: const u8[:]) -> bool {
    var low: u8[>..] = [];
    lower_of(path, low);
    return has_word(low[..], word);
}

// is_weak_hash_name reports whether the name is a weak hash function or
// the module of one.
fn is_weak_hash_name(name: const u8[:]) -> bool {
    return name == "md5" || name == "sha1" || name == "md4"
        || name == "ripemd160" || name == "Md5" || name == "Sha1";
}

// is_weak_rand_name reports whether the name is a weak random function.
fn is_weak_rand_name(name: const u8[:]) -> bool {
    return name == "rand_u64" || name == "rand_int" || name == "rand_flt"
        || name == "shuffle";
}

// qual_call reports whether the token i is the qualifier of a call of
// the form `module::name(`. The called name must not be a weak function
// itself, because the bare call rule reports that name already.
fn qual_call(src: const u8[:], i: i64) -> bool {
    if i + 4 >= tk_count { return false; }
    if tk_kind[i + 1] != TK_OTHER || tok_of(src, i + 1) != ":" { return false; }
    if tk_kind[i + 2] != TK_OTHER || tok_of(src, i + 2) != ":" { return false; }
    if tk_kind[i + 3] != TK_IDENT { return false; }
    if tk_kind[i + 4] != TK_OTHER || tok_of(src, i + 4) != "(" { return false; }
    let called = tok_of(src, i + 3);
    return !is_weak_hash_name(called) && !is_weak_rand_name(called);
}

// qual_is_weak_hash reports whether the qualifier of a call names a
// weak hash. The name of the module counts when it names one. An
// import that came from a weak hash package counts too, so the name of
// the import may hold anything. gosec and bandit read the import table
// in the same way.
fn qual_is_weak_hash(src: const u8[:], i: i64) -> bool {
    let name = tok_of(src, i);
    if is_weak_hash_name(name) { return true; }
    let idx = imp_find(name);
    if idx < 0 { return false; }
    let path = imp_path(idx);
    return path_names(path, "md5") || path_names(path, "sha1")
        || path_names(path, "md4") || path_names(path, "ripemd160");
}

// qual_is_weak_rand reports whether the qualifier of a call names a
// weak random source.
fn qual_is_weak_rand(src: const u8[:], i: i64) -> bool {
    let name = tok_of(src, i);
    if name == "rand" { return true; }
    let idx = imp_find(name);
    if idx < 0 { return false; }
    return path_names(imp_path(idx), "rand");
}

// rule_weakhash runs G401: a call of md5, sha1, md4 or ripemd160. The
// rule reads the tokens around the name, so a variable or a function
// that carries the name does not report. A call through the name of an
// imported module reports too, when the module came from a weak hash
// package.
fn rule_weakhash(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    read_imports(src);
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && is_call(src, i) {
            let name = tok_of(src, i);
            if is_weak_hash_name(name) {
                rep(out, 13, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                    "a weak hash is in use");
            }
        } else if tk_kind[i] == TK_IDENT && qual_call(src, i)
            && qual_is_weak_hash(src, i) {
            // A call through the module name, as in md5::sum(data).
            rep(out, 13, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                "a weak hash is in use");
        }
        i = i + 1;
    }
}

// rule_weakrand runs G404: the non-crypto random calls of the standard
// library, and a constant-seeded rng literal.
fn rule_weakrand(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    read_imports(src);
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT {
            let name = tok_of(src, i);
            if is_weak_rand_name(name) && is_call(src, i) {
                rep(out, 14, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                    "a weak random source is in use");
            } else if name == "rng" && i + 1 < tk_count && tk_kind[i + 1] == TK_OTHER
                && tok_of(src, i + 1) == "{"
                && i + 2 < tk_count && tk_kind[i + 2] == TK_NUMBER {
                rep(out, 14, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                    "a weak random source is in use");
            } else if qual_call(src, i) && qual_is_weak_rand(src, i) {
                // A call through the module name, as in rand::int(10).
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
    if has_word(low[..], "xmlrpc") { return reg_find("B411"); }
    if has_word(low[..], "lxml") { return reg_find("B410"); }
    return -1;
}

// rule_blocklist runs G501 to G507 and B401 to B404, B410 and B411:
// the import lines of the blocklist. Each import line reports at most
// one row; the gosec rows win over the bandit rows.
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
