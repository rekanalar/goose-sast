// The credential and file rules: the hardcoded credentials, the bind
// addresses, the temp and variable paths, and the permission literals.
namespace sast;

// rep builds one finding from the registry row of the rule index.
fn rep(out: Finding[>..]&, idx: i64, file_idx: i64, line: i64, col: i64,
       msg: const u8[:]) {
    reg_ensure();
    let at = buf_texts.len;
    var i: i64 = 0;
    while i < msg.len { buf_texts.push(msg[i]); i = i + 1; }
    out.push(Finding {
        rule: idx, sev: reg_sev_s[idx], conf: reg_conf_s[idx],
        cwe: reg_cwe_s[idx], file: file_idx, line: line, col: col,
        msg: at, msg_end: buf_texts.len,
    });
}

// lower_of gives the lowercase form of s, into out.
fn lower_of(s: const u8[:], out: u8[>..]&) {
    for b in s {
        if b >= 65 && b <= 90 { out.push(b + 32); } else { out.push(b); }
    }
}

// has_word reports whether the lowercase text holds the word.
fn has_word(text: const u8[:], word: const u8[:]) -> bool {
    var i: i64 = 0;
    while i + word.len <= text.len {
        if text[i..i + word.len] == word { return true; }
        i = i + 1;
    }
    return false;
}

// The classes of a name that names a credential. A strong name needs
// only a literal of some value. A weak name needs a literal that
// looks like a credential.
const SECRET_NONE: i64 = 0;
const SECRET_WEAK: i64 = 1;
const SECRET_STRONG: i64 = 2;

// secret_class gives the class of a name. The name is lowercased and
// read as a substring, as the rule did before. The strong list is
// checked first, so the name password is strong and the name bypass is
// weak. The name key is no name of a credential.
fn secret_class(name: const u8[:]) -> i64 {
    var low: u8[>..] = [];
    lower_of(name, low);
    if has_word(low[..], "password") || has_word(low[..], "passwd")
        || has_word(low[..], "passphrase") || has_word(low[..], "secret")
        || has_word(low[..], "token") || has_word(low[..], "apikey")
        || has_word(low[..], "api_key") || has_word(low[..], "privatekey")
        || has_word(low[..], "private_key") {
        return SECRET_STRONG;
    }
    if has_word(low[..], "pass") || has_word(low[..], "pwd") {
        return SECRET_WEAK;
    }
    return SECRET_NONE;
}

// secret_literal reports whether the body of a literal holds a
// credential of the class. A strong name needs a body of at least 2
// bytes with one byte above 32, so a space inside is allowed. A weak
// name needs a body of at least 8
// bytes with no byte of 32 or less and more than one distinct byte.
// An empty body, a body of one byte and a body of spaces never
// report, for any name.
fn secret_literal(body: const u8[:], class: i64) -> bool {
    if body.len < 2 { return false; }
    var i: i64 = 0;
    if class == SECRET_STRONG {
        while i < body.len {
            if body[i] > 32 { return true; }
            i = i + 1;
        }
        return false;
    }
    if body.len < 8 { return false; }
    var distinct = false;
    while i < body.len {
        if body[i] <= 32 { return false; }
        if body[i] != body[0] { distinct = true; }
        i = i + 1;
    }
    return distinct;
}

// rule_cred runs G101: a string literal bound to a secret-named name.
// The name and the literal must sit on the same line, so a secret name
// of one function does not match a literal of another.
fn rule_cred(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT {
            let class = secret_class(tok_of(src, i));
            if class != SECRET_NONE {
                // The name is bound by an = or a : and takes a literal.
                var k = i + 1;
                var bound = false;
                while k < tk_count && tk_line[k] == tk_line[i] {
                    if tk_kind[k] == TK_OTHER
                        && (tok_of(src, k) == "=" || tok_of(src, k) == ":") {
                        bound = true;
                        break;
                    }
                    k = k + 1;
                }
                if bound {
                    var m = k + 1;
                    while m < tk_count && tk_line[m] == tk_line[i] {
                        if tk_kind[m] == TK_STRING {
                            let lit = tok_of(src, m);
                            if lit.len > 2 {
                                let body = lit[1..lit.len - 1];
                                if secret_literal(body, class) {
                                    rep(out, 0, file_idx, tk_line[i],
                                        tok_col_of(src, tk_start[i]),
                                        "a credential may be hardcoded");
                                }
                            }
                            break;
                        }
                        if tk_kind[m] == TK_OTHER && tok_of(src, m) == ")" { break; }
                        m = m + 1;
                    }
                }
            }
        }
        i = i + 1;
    }
}

// is_bind_call reports whether the identifier names a bind call. The
// name is read in lower case, so the letter case does not matter.
fn is_bind_call(name: const u8[:]) -> bool {
    var low: u8[>..] = [];
    lower_of(name, low);
    return has_word(low[..], "listen") || has_word(low[..], "bind")
        || has_word(low[..], "serve") || has_word(low[..], "accept");
}

// bind_callee gives the callee of the call that holds the literal at
// the token i. It gives an empty text when the literal sits in no call.
// The rule walks back to the open bracket that holds the literal. The
// token before that bracket is the callee. The walk stops at a
// statement end or at 32 tokens, so the work stays constant.
fn bind_callee(src: const u8[:], i: i64) -> const u8[:] {
    var depth: i64 = 0;
    var braces: i64 = 0;
    var k = i - 1;
    var steps: i64 = 0;
    while k >= 0 && steps < 32 {
        if tk_kind[k] == TK_OTHER {
            let t = tok_of(src, k);
            if t == ")" { depth = depth + 1; }
            else if t == "(" {
                if depth == 0 {
                    if k == 0 { return ""; }
                    if tk_kind[k - 1] != TK_IDENT { return ""; }
                    return tok_of(src, k - 1);
                }
                depth = depth - 1;
            } else if t == "}" {
                braces = braces + 1;
            } else if t == "{" {
                // A brace pair before the literal is a value of the call.
                if braces == 0 { return ""; }
                braces = braces - 1;
            } else if t == ";" && braces == 0 && depth == 0 {
                return "";
            }
        }
        k = k - 1;
        steps = steps + 1;
    }
    return "";
}

// rule_bind runs G102: a bind-all address literal in a bind call. The
// literal alone is no bind, so the rule reads the callee of the call
// that holds it.
fn rule_bind(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_STRING {
            let lit = tok_of(src, i);
            // A string that never closed holds its quote only.
            if lit.len > 1 {
                let body = lit[1..lit.len - 1];
                if body == "0.0.0.0" || body == "::" || body == "[::]" {
                    let callee = bind_callee(src, i);
                    if callee.len > 0 && is_bind_call(callee) {
                        rep(out, 1, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]),
                            "the program binds to all interfaces");
                    }
                }
            }
        }
        i = i + 1;
    }
}

// is_path_call reports whether the identifier names a file call.
fn is_path_call(name: const u8[:]) -> bool {
    return name == "read_file" || name == "write_file"
        || name == "append_file" || name == "delete_file"
        || name == "rename_file" || name == "make_dir"
        || name == "list_dir" || name == "file_exists"
        || name == "is_dir" || name == "write_file_atomic";
}

// in_path_call reports whether the token i sits in the argument list
// of a file call. The call name sits on the same line, before the
// literal, and holds an open bracket between the name and the
// literal.
fn in_path_call(src: const u8[:], i: i64) -> bool {
    var k = i - 1;
    while k >= 0 && tk_line[k] == tk_line[i] && i - k <= 16 {
        if tk_kind[k] == TK_IDENT && is_path_call(tok_of(src, k))
            && k + 1 < tk_count && tk_kind[k + 1] == TK_OTHER
            && tok_of(src, k + 1) == "(" {
            return true;
        }
        if tk_kind[k] == TK_OTHER && (tok_of(src, k) == ";"
            || tok_of(src, k) == "}") {
            return false;
        }
        k = k - 1;
    }
    return false;
}

// rule_paths runs G303, G304 and G111: the temp paths, the variable
// paths of the file calls, and the root path literal.
fn rule_paths(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_STRING {
            let lit = tok_of(src, i);
            if lit.len > 1 {
                let body = lit[1..lit.len - 1];
                // The literal must sit in the argument list of a file
                // call. A separator push or a format call does not.
                if in_path_call(src, i) {
                    if body == "/" {
                        rep(out, 15, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]), "the path is the root directory");
                    } else if has_word(body, "/tmp/") || has_word(body, "/var/tmp/") {
                        rep(out, 10, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]), "a temp path is predictable");
                    }
                }
            }
        } else if tk_kind[i] == TK_IDENT && is_call(src, i) {
            // A file call whose first argument is an identifier.
            let name = tok_of(src, i);
            if is_path_call(name) {
                var k = i + 2;
                while k < tk_count && tk_line[k] == tk_line[i] {
                    if tk_kind[k] == TK_IDENT && tok_of(src, k) != "copy" {
                        rep(out, 11, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]),
                            "a file path comes from a variable");
                        break;
                    }
                    if tk_kind[k] == TK_OTHER && tok_of(src, k) == ")" { break; }
                    k = k + 1;
                }
            }
        }
        i = i + 1;
    }
}

// oct_value gives the value of an octal literal such as 0o644. It gives
// -1 for any other number text.
fn oct_value(text: const u8[:]) -> i64 {
    // Only the 0o form is a permission literal. A decimal is a count.
    if text.len < 3 || text[0] != 48 || text[1] != 111 { return -1; }
    var v: i64 = 0;
    var i: i64 = 2;
    while i < text.len {
        let d = text[i] - 48;
        if d >= 8 { return -1; }
        v = v * 8 + d;
        i = i + 1;
    }
    return v;
}

// rule_modes runs G301, G302, G306 and B103: the permission literals.
// A world or group writable mode is G302, and 0777 is also B103. A
// mode above 0600 on a name that holds write is G306. A mode beside a
// directory call is G301.
fn rule_modes(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_NUMBER {
            let text = tok_of(src, i);
            let v = oct_value(text);
            if v >= 0 && v <= 511 {
                let world = v & 2;
                let group = v & 16;
                // The line holds the call the mode belongs to.
                var k = tok_find_line_start( tk_line[i]);
                var call_k: i64 = -1;
                while k < tk_count && tk_line[k] == tk_line[i] {
                    if tk_kind[k] == TK_IDENT && k + 1 < tk_count
                        && tk_kind[k + 1] == TK_OTHER
                        && tok_of(src, k + 1) == "(" {
                        call_k = k;
                        break;
                    }
                    k = k + 1;
                }
                var call: u8[>..] = [];
                if call_k >= 0 { for b in tok_of(src, call_k) { call.push(b); } }
                if world != 0 {
                    // B103 is the alias of G302, so one row reports it.
                    rep(out, 9, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                        "file permissions are too wide");
                } else if v > 384 {
                    if has_word(call[..], "write") || has_word(call[..], "append") {
                        rep(out, 12, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]), "a write gets wide permissions");
                    } else if has_word(call[..], "dir") {
                        rep(out, 8, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]), "a directory gets wide permissions");
                    } else {
                        rep(out, 9, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]), "file permissions are too wide");
                    }
                }
            }
        }
        i = i + 1;
    }
}
