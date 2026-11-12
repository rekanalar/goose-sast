// The language rules: the narrowing casts, the bidi characters, the
// asserts, the empty catch bodies and the time limits.
namespace sast;

// rule_cast runs G109: an `as!` cast whose target type is a smaller
// integer type. G115 is the alias.
fn rule_cast(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "as"
            && i + 1 < tk_count && tk_kind[i + 1] == TK_OTHER
            && tok_of(src, i + 1) == "!"
            && i + 2 < tk_count && tk_kind[i + 2] == TK_IDENT {
            let ty = tok_of(src, i + 2);
            if ty == "i8" || ty == "i16" || ty == "i32" || ty == "u8"
                || ty == "u16" || ty == "u32" {
                rep(out, 2, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                    "a narrowing cast may lose bits");
            }
        }
        i = i + 1;
    }
}

// rule_bidi runs G116: a bidirectional control character anywhere in
// the source. B613 is the alias.
fn rule_bidi(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    var line: i64 = 1;
    var col: i64 = 1;
    while i < src.len {
        let b = src[i];
        // The bidi characters start with the byte 226 (0xE2) and sit in
        // the ranges U+202A to U+202E and U+2066 to U+2069, plus the
        // marks U+200E, U+200F and U+061C.
        if b == 226 && i + 2 < src.len {
            let m = src[i + 1];
            let l = src[i + 2];
            let marks = (m == 0x80 && l >= 0xAA && l <= 0xAE)
                || (m == 0x81 && l >= 0xA6 && l <= 0xA9);
            if marks {
                rep(out, 3, file_idx, line, col,
                    "the source holds bidirectional control characters");
            }
        } else if b == 216 && i + 1 < src.len && src[i + 1] == 156
            && i + 2 < src.len && src[i + 2] >= 156 && src[i + 2] <= 159 {
            // U+061C, the Arabic letter mark, in 0xD8 0x9C to 0xD8 0x9F.
            rep(out, 3, file_idx, line, col,
                "the source holds bidirectional control characters");
        } else if b == 226 && i + 2 < src.len && src[i + 1] == 0x80
            && (src[i + 2] == 0x8E || src[i + 2] == 0x8F) {
            rep(out, 3, file_idx, line, col,
                "the source holds bidirectional control characters");
        }
        if b == 10 { line = line + 1; col = 1; } else { col = col + 1; }
        i = i + 1;
    }
}

// in_test_file reports whether the path names a test file.
fn in_test_file(path: const u8[:]) -> bool {
    var low: u8[>..] = [];
    lower_of(path, low);
    return has_word(low[..], "test");
}

// rule_assert runs B101: an assert call in a file that is not a test.
fn rule_assert(path: const u8[:], src: const u8[:],
               file_idx: i64, out: Finding[>..]&) {
    if in_test_file(path) { return; }
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "assert"
            && i + 1 < tk_count && tk_kind[i + 1] == TK_OTHER
            && tok_of(src, i + 1) == "(" {
            rep(out, 16, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                "an assert may be removed in a release build");
        }
        i = i + 1;
    }
}

// rule_emptycatch runs B110: a try call whose trailing block holds no
// token. B112 is the alias. The lexer gives each colon as one token, so
// the qualified name holds two.
fn rule_emptycatch(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "try"
            && i > 2 && tk_kind[i - 1] == TK_OTHER && tok_of(src, i - 1) == ":"
            && tk_kind[i - 2] == TK_OTHER && tok_of(src, i - 2) == ":"
            && tk_kind[i - 3] == TK_IDENT && tok_of(src, i - 3) == "exception" {
            // Find the last brace of the line group that follows.
            var k = i + 1;
            var opened = -1;
            while k < tk_count && tk_line[k] <= tk_line[i] + 40 {
                if tk_kind[k] == TK_OTHER && tok_of(src, k) == "{" {
                    opened = k;
                } else if opened >= 0 && tk_kind[k] == TK_OTHER
                    && tok_of(src, k) == "}" {
                    // The block holds a token when the open sits before
                    // the close in the token list.
                    if opened + 1 == k {
                        rep(out, 17, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]),
                            "a catch body holds nothing");
                    }
                    break;
                }
                k = k + 1;
            }
        }
        i = i + 1;
    }
}

// rule_timeout runs B113: a wait call whose time limit is a literal 0.
fn rule_timeout(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "wait"
            && i + 1 < tk_count && tk_kind[i + 1] == TK_OTHER
            && tok_of(src, i + 1) == "(" {
            // The second argument is the limit. A literal 0 is the
            // missing limit.
            var depth: i64 = 0;
            var commas: i64 = 0;
            var k = i + 2;
            while k < tk_count && tk_line[k] <= tk_line[i] + 4 {
                if tk_kind[k] == TK_OTHER {
                    let ch = tok_of(src, k);
                    if ch == "(" { depth = depth + 1; }
                    else if ch == ")" {
                        depth = depth - 1;
                        if depth < 0 { break; }
                    }
                    else if ch == "," && depth == 0 { commas = commas + 1; }
                }
                if tk_kind[k] == TK_NUMBER && commas == 1 && depth == 0
                    && tok_of(src, k) == "0" {
                    rep(out, 18, file_idx, tk_line[i],
                        tok_col_of(src, tk_start[i]),
                        "a wait takes no time limit");
                }
                k = k + 1;
            }
        }
        i = i + 1;
    }
}

// rule_extern runs G103: an extern declaration binds code that the
// type checker cannot see.
fn rule_extern(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    let idx = reg_find("G103");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "extern"
            && i + 1 < tk_count && tk_kind[i + 1] == TK_STRING {
            rep(out, idx, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                "an extern function calls code outside the type checker");
        }
        i = i + 1;
    }
}

// rule_secretjson runs G117: a secret-named identifier on the line of
// a call to a JSON writer.
fn rule_secretjson(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    let idx = reg_find("G117");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && tok_of(src, i) == "json"
            && i + 3 < tk_count && tok_of(src, i + 1) == ":"
            && tok_of(src, i + 2) == ":" && tk_kind[i + 3] == TK_IDENT
            && has_word(tok_of(src, i + 3), "format") {
            var k = i + 4;
            while k < tk_count && tk_line[k] == tk_line[i] {
                if tk_kind[k] == TK_IDENT
                    && secret_class(tok_of(src, k)) != SECRET_NONE {
                    rep(out, idx, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                        "a secret-named value goes into a JSON writer");
                    break;
                }
                k = k + 1;
            }
        }
        i = i + 1;
    }
}

// is_bool_call reports whether the name is a call that gives a bool. The
// file calls and the process calls give one.
fn is_bool_call(name: const u8[:]) -> bool {
    return name == "write_file" || name == "append_file"
        || name == "delete_file" || name == "rename_file"
        || name == "make_dir" || name == "file_exists"
        || name == "is_dir" || name == "write_file_atomic";
}

// rule_dropped runs G104: a call that gives a bool, and whose result
// nobody reads. The result is dropped when the call sits alone on its
// statement.
fn rule_dropped(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    let idx = reg_find("G104");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && is_bool_call(tok_of(src, i))
            && i + 1 < tk_count && tk_kind[i + 1] == TK_OTHER
            && tok_of(src, i + 1) == "(" {
            // Find the end of the call.
            var depth: i64 = 0;
            var k = i + 1;
            var end = i + 1;
            while k < tk_count && tk_line[k] <= tk_line[i] + 8 {
                if tk_kind[k] == TK_OTHER {
                    let ch = tok_of(src, k);
                    if ch == "(" { depth = depth + 1; }
                    else if ch == ")" {
                        depth = depth - 1;
                        if depth == 0 { end = k; break; }
                    }
                }
                k = k + 1;
            }
            // A result is used when the statement binds it, guards on
            // it or returns it. A call that stands alone drops it.
            var used = false;
            var j = i - 1;
            while j >= 0 && tk_line[j] >= tk_line[i] - 2 && i - j <= 8 {
                if tk_kind[j] == TK_OTHER {
                    let ch = tok_of(src, j);
                    if ch == "=" || ch == ":" || ch == "&&" || ch == "||" {
                        used = true;
                        break;
                    }
                }
                if tk_kind[j] == TK_IDENT {
                    let w = tok_of(src, j);
                    if w == "if" || w == "guard" || w == "return"
                        || w == "while" || w == "and" || w == "or" {
                        used = true;
                        break;
                    }
                }
                j = j - 1;
            }
            if used { i = end; continue; }
            if end + 1 < tk_count {
                let next = tk_kind[end + 1];
                let nxt = tok_of(src, end + 1);
                if next == TK_OTHER && (nxt == ";" || nxt == ")" || nxt == ",") {
                    rep(out, idx, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                        "the result of the call is dropped");
                }
            }
        }
        i = i + 1;
    }
}

// is_number_word reports whether the text is a decimal number.
fn is_number_word(text: const u8[:]) -> bool {
    if text.len == 0 { return false; }
    var i: i64 = 0;
    while i < text.len {
        if text[i] < 48 || text[i] > 57 { return false; }
        i = i + 1;
    }
    return true;
}
