// The tokenizer of the linter. It reads Goose source as bytes and
// splits it into tokens: identifiers, strings, numbers, comments and
// single other bytes. Each token holds its line, counted from 1. The
// rules walk the token list; no rule reads inside a string it does not
// need.
namespace sast;

// The token kinds.
const TK_IDENT: i64 = 1;
const TK_STRING: i64 = 2;
const TK_NUMBER: i64 = 3;
const TK_COMMENT: i64 = 4;
const TK_OTHER: i64 = 5;

// The tokens of the file that the scanner holds now. One file sits in
// the columns at a time; tokenize() refills them.
var tk_kind: i64[>..] = [];
var tk_start: i64[>..] = [];
var tk_end: i64[>..] = [];
var tk_line: i64[>..] = [];
var tk_count: i64 = 0;

// tok_reset empties the columns before a file.
fn tok_reset() {
    tk_kind.resize(0, 0);
    tk_start.resize(0, 0);
    tk_end.resize(0, 0);
    tk_line.resize(0, 0);
    tk_count = 0;
}

// tok_push appends one token.
fn tok_push(kind: i64, start: i64, end: i64, line: i64) {
    tk_kind.push(kind);
    tk_start.push(start);
    tk_end.push(end);
    tk_line.push(line);
    tk_count = tk_count + 1;
}

// is_ident_byte reports whether the byte sits in an identifier.
fn is_ident_byte(b: u8) -> bool {
    return (b >= 48 && b <= 57) || (b >= 65 && b <= 90)
        || (b >= 97 && b <= 122) || b == 95;
}

// tok_of gives the text of the token i as a slice of src.
fn tok_of(src: const u8[:], i: i64) -> const u8[:] {
    return src[tk_start[i]..tk_end[i]];
}

// tok_line_of gives the line, counted from 1, of the byte at.
fn tok_line_of(src: const u8[:], at: i64) -> i64 {
    var line: i64 = 1;
    var k: i64 = 0;
    while k < at && k < src.len {
        if src[k] == 10 { line = line + 1; }
        k = k + 1;
    }
    return line;
}

// tok_col_of gives the column, counted from 1, of the byte at.
fn tok_col_of(src: const u8[:], at: i64) -> i64 {
    var col: i64 = 1;
    var k: i64 = at;
    while k > 0 && src[k - 1] != 10 { col = col + 1; k = k - 1; }
    return col;
}

// tokenize splits src into tokens. A string holds its quotes and runs
// to the end of the line when the quote never closes. A comment runs
// to the end of the line. A number holds the 0o and 0x forms.
fn tokenize(src: const u8[:]) {
    tok_reset();
    var i: i64 = 0;
    var line: i64 = 1;
    while i < src.len {
        let b = src[i];
        if b == 10 {
            line = line + 1;
            i = i + 1;
        } else if b == 32 || b == 9 || b == 13 {
            i = i + 1;
        } else if b == 47 && i + 1 < src.len && src[i + 1] == 47 {
            // A comment runs to the end of the line.
            let at = i;
            while i < src.len && src[i] != 10 { i = i + 1; }
            tok_push(TK_COMMENT, at, i, line);
        } else if b == 34 || b == 39 {
            // A string holds its quotes. A backslash skips the next
            // byte. A string that never closes ends at the line end.
            let at = i;
            let q = b;
            i = i + 1;
            while i < src.len && src[i] != q && src[i] != 10 {
                if src[i] == 92 && i + 1 < src.len { i = i + 1; }
                i = i + 1;
            }
            if i < src.len && src[i] == q { i = i + 1; }
            tok_push(TK_STRING, at, i, line);
        } else if b >= 48 && b <= 57 {
            let at = i;
            i = i + 1;
            if b == 48 && i < src.len && (src[i] == 111 || src[i] == 120) {
                // The 0o and 0x forms take letters and digits.
                i = i + 1;
                while i < src.len && ((src[i] >= 48 && src[i] <= 57)
                    || (src[i] >= 97 && src[i] <= 102)
                    || (src[i] >= 65 && src[i] <= 70)) { i = i + 1; }
            } else {
                while i < src.len && ((src[i] >= 48 && src[i] <= 57)
                    || src[i] == 46 || src[i] == 95) { i = i + 1; }
            }
            tok_push(TK_NUMBER, at, i, line);
        } else if is_ident_byte(b) {
            let at = i;
            while i < src.len && is_ident_byte(src[i]) { i = i + 1; }
            tok_push(TK_IDENT, at, i, line);
        } else {
            tok_push(TK_OTHER, i, i + 1, line);
            i = i + 1;
        }
    }
}

// tok_find_line_start gives the index of the first token of the line.
fn tok_find_line_start(line: i64) -> i64 {
    var i: i64 = 0;
    while i < tk_count {
        if tk_line[i] == line { return i; }
        i = i + 1;
    }
    return tk_count;
}

// tok_line_holds_comment reports whether the line holds a comment
// token. It gives the index of the comment, or -1.
fn tok_line_comment(line: i64) -> i64 {
    var i: i64 = 0;
    while i < tk_count {
        if tk_line[i] == line && tk_kind[i] == TK_COMMENT { return i; }
        if tk_line[i] > line { return -1; }
        i = i + 1;
    }
    return -1;
}
