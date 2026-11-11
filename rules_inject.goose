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
                rep(out, 4, file_idx, line, tok_col_of(src, tk_start[i]),
                    "a SQL query is built with a format call");
            } else if concat {
                rep(out, 5, file_idx, line, tok_col_of(src, tk_start[i]),
                    "a SQL query is built by concatenation");
            }
        }
        i = i + 1;
    }
}

// rule_html runs G203: a tag-like literal concatenated with an
// identifier on the same line.
fn rule_html(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
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
                    rep(out, 6, file_idx, line, tok_col_of(src, tk_start[i]),
                        "HTML is built from a variable");
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
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT && is_proc_call(tok_of(src, i))
            && i + 1 < tk_count && tk_kind[i + 1] == TK_OTHER
            && tok_of(src, i + 1) == "(" {
            // The command is the first argument.
            var k = i + 2;
            while k < tk_count && tk_line[k] == tk_line[i] {
                if tk_kind[k] == TK_IDENT {
                    rep(out, 7, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                        "a command is built from a variable");
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
                        rep(out, 19, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]),
                            "a command holds a partial path");
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

// rule_wildcard runs B609: a literal `*` argument to any call.
fn rule_wildcard(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_STRING && lit_body(tok_of(src, i)) == "*"
            && i > 0 && tk_kind[i - 1] == TK_OTHER
            && (tok_of(src, i - 1) == "(" || tok_of(src, i - 1) == ",") {
            rep(out, 20, file_idx, tk_line[i], tok_col_of(src, tk_start[i]),
                "a wildcard may expand in a command");
        }
        i = i + 1;
    }
}
