// The injection rules: the SQL strings, the HTML, the process commands
// and the wildcard arguments.
namespace sast;

// lit_body gives the text between the quotes of a string token.
fn lit_body(lit: const u8[:]) -> const u8[:] {
    if lit.len >= 2 { return lit[1..lit.len - 1]; }
    return lit;
}

// holds_sql reports whether the text holds a SQL keyword.
fn holds_sql(text: const u8[:]) -> bool {
    var low: u8[>..] = [];
    lower_of(text, low);
    return has_word(low[..], "select") || has_word(low[..], "insert")
        || has_word(low[..], "update") || has_word(low[..], "delete from");
}

// rule_sql runs G201 and G202: a SQL literal is G202, and B608 is its
// alias. A SQL literal built with a format or a str call on the same
// line is G201. The parts of the query may sit on several lines, so the
// rule reads the tokens of the statement, not the line.
fn rule_sql(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    let g201 = reg_must("G201");
    let g202 = reg_must("G202");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_STRING && holds_sql(lit_body(tok_of(src, i))) {
            let line = tk_line[i];
            // The statement ends at the next semicolon.
            var end = i;
            while end < tk_count && tk_line[end] <= line + 8 {
                if tk_kind[end] == TK_OTHER && tok_of(src, end) == ";" { break; }
                end = end + 1;
            }
            var fmtcall = false;
            var concat = false;
            var k = i;
            while k < end {
                if tk_kind[k] == TK_IDENT
                    && (tok_of(src, k) == "str" || tok_of(src, k) == "format"
                        || tok_of(src, k) == "format_replaced") {
                    fmtcall = true;
                }
                if tk_kind[k] == TK_OTHER && tok_of(src, k) == "+" {
                    concat = true;
                }
                k = k + 1;
            }
            if fmtcall {
                rep(out, g201, file_idx, line, tok_col_of(src, tk_start[i]));
            } else if concat {
                rep(out, g202, file_idx, line, tok_col_of(src, tk_start[i]));
            }
        }
        i = i + 1;
    }
}

// rule_html runs G203: a tag-like literal concatenated with an
// identifier on the same line.
fn rule_html(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    let g203 = reg_must("G203");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_STRING {
            let body = lit_body(tok_of(src, i));
            if is_tag_like(body) {
                let line = tk_line[i];
                var k = tok_find_line_start( line);
                var concat = false;
                while k < tk_count && tk_line[k] == line {
                    if tk_kind[k] == TK_OTHER && tok_of(src, k) == "+"
                        && k + 1 < tk_count && tk_line[k + 1] == line
                        && tk_kind[k + 1] == TK_IDENT {
                        concat = true;
                    }
                    k = k + 1;
                }
                if concat {
                    rep(out, g203, file_idx, line, tok_col_of(src, tk_start[i]));
                }
            }
        }
        i = i + 1;
    }
}

// is_tag_like reports whether the text holds a `<` followed by a
// letter, the shape of an HTML tag.
fn is_tag_like(text: const u8[:]) -> bool {
    var i: i64 = 0;
    while i + 1 < text.len {
        if text[i] == 60 && ((text[i + 1] >= 97 && text[i + 1] <= 122)
            || (text[i + 1] >= 65 && text[i + 1] <= 90)) {
            return true;
        }
        i = i + 1;
    }
    return false;
}

// is_proc_call reports whether the identifier names a process call.
fn is_proc_call(name: const u8[:]) -> bool {
    return name == "run" || name == "spawn";
}

// rule_proc runs G204 and B607: a process call whose command argument
// is a variable is G204; a command literal with no path separator is
// B607.
fn rule_proc(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    let g204 = reg_must("G204");
    let b607 = reg_must("B607");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && is_proc_call(tok_of(src, i))
            && is_call(src, i) {
            // The command is the first argument.
            var k = i + 2;
            while k < tk_count && tk_line[k] == tk_line[i] {
                if tk_kind[k] == TK_IDENT {
                    rep(out, g204, file_idx, tk_line[i], tok_col_of(src, tk_start[i]));
                    break;
                }
                if tk_kind[k] == TK_STRING {
                    let body = lit_body(tok_of(src, k));
                    var sep = false;
                    var j: i64 = 0;
                    while j < body.len {
                        if body[j] == 47 { sep = true; }
                        j = j + 1;
                    }
                    if !sep {
                        rep(out, b607, file_idx, tk_line[i], tok_col_of(src, tk_start[i]));
                    }
                    break;
                }
                if tk_kind[k] == TK_OTHER && tok_of(src, k) == ")" { break; }
                k = k + 1;
            }
        }
        i = i + 1;
    }
}

// enclosing_call gives the name of the call that holds the token i in
// its argument list. The name sits before the literal, on the same
// line. It gives an empty text when no call holds the token.
fn enclosing_call(src: const u8[:], i: i64) -> const u8[:] {
    var k = i - 1;
    while k >= 0 && tk_line[k] == tk_line[i] && i - k <= 16 {
        if tk_kind[k] == TK_IDENT && k + 1 < tk_count
            && tk_kind[k + 1] == TK_OTHER && tok_of(src, k + 1) == "(" {
            return tok_of(src, k);
        }
        if tk_kind[k] == TK_OTHER && (tok_of(src, k) == ";"
            || tok_of(src, k) == "}") {
            return "";
        }
        k = k - 1;
    }
    return "";
}

// rule_wildcard runs B609: a literal `*` argument to a process call.
// The wildcard expands only where a command runs.
fn rule_wildcard(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    let b609 = reg_must("B609");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_STRING && lit_body(tok_of(src, i)) == "*"
            && i > 0 && tk_kind[i - 1] == TK_OTHER
            && (tok_of(src, i - 1) == "(" || tok_of(src, i - 1) == ",") {
            let call = enclosing_call(src, i);
            if is_proc_call(call) {
                rep(out, b609, file_idx, tk_line[i], tok_col_of(src, tk_start[i]));
            }
        }
        i = i + 1;
    }
}
