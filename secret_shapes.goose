// The built-in secret shapes: S101 an AWS access key ID, S102 a GitHub
// token, S103 a Slack token and S104 a private key header. The shapes
// search the whole text of a file, so a secret in a comment reports too.
// A finding holds a fixed message and no byte of the match.
namespace sast;

import regex;

// The compiled expressions, in the order of the shape rows. A row that
// starts with a boundary byte holds a class of one byte first, because
// the engine has no word boundary and no look-behind. A candidate that
// follows a letter is then no match and it consumes nothing.
//   row 0: S101 the AWS access key ID
//   row 1: S102 the classic GitHub token
//   row 2: S102 the fine-grained GitHub token
//   row 3: S103 the Slack bot, user and refresh tokens
//   row 4: S103 the Slack app token
//   row 5: S104 the private key header
const SHAPE_ROWS: i64 = 6;
var shape_re: regex::Regex[>..] = [];
var shape_ready: bool = false;

// The registry index of S101 to S104.
var shape_rule: i64[>..] = [];

// shape_text gives the expression of a row.
fn shape_text(row: i64) -> const u8[:] {
    if row == 0 { return "[^A-Za-z0-9](?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}"; }
    if row == 1 { return "[^A-Za-z0-9]gh[pousr]_[A-Za-z0-9]{36}"; }
    if row == 2 { return "[^A-Za-z0-9_]github_pat_[A-Za-z0-9_]{82}"; }
    if row == 3 { return "[^A-Za-z0-9]xox[bpars]-[A-Za-z0-9-]{10,72}"; }
    if row == 4 { return "[^A-Za-z0-9]xapp-[0-9]-[A-Za-z0-9-]{10,80}"; }
    return "-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----";
}

// shape_owner gives the place of the rule of a row among S101 to S104.
fn shape_owner(row: i64) -> i64 {
    if row == 0 { return 0; }
    if row == 1 || row == 2 { return 1; }
    if row == 3 || row == 4 { return 2; }
    return 3;
}

// shape_ensure compiles the six expressions once. A later call does
// nothing. The expressions are constants that the tests compile, so a
// failure here is a fault of the program.
fn shape_ensure() {
    if shape_ready { return; }
    reg_ensure();
    shape_rule = [];
    shape_rule.push(reg_find("S101"));
    shape_rule.push(reg_find("S102"));
    shape_rule.push(reg_find("S103"));
    shape_rule.push(reg_find("S104"));
    shape_re = [];
    var row: i64 = 0;
    while row < SHAPE_ROWS {
        var err: u8[>..] = [];
        let re = regex::compile(shape_text(row), err);
        if err.len > 0 { abort("a secret shape does not compile"); }
        shape_re.push(copy(re));
        row = row + 1;
    }
    shape_ready = true;
}

// shape_alnum reports whether the byte is a letter or a digit.
fn shape_alnum(b: u8) -> bool {
    return (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122);
}

// shape_body reports whether the byte is a body byte of the rows 3 and
// 4. These rows hold a letter, a digit or a hyphen.
fn shape_body(b: u8) -> bool {
    return shape_alnum(b) || b == 45;
}

// shape_after_ok reports whether the byte at e ends the shape of the row.
// The index e is the place of the byte after the match. The end of the
// file ends a shape. The rows 0, 1 and 2 hold a fixed body, so a body
// byte after the match means the body is too long. The rows 3 and 4 hold
// a body with a maximum, so a body byte after the match means the body
// is longer than the maximum. The row 5 checks no byte after the match.
fn shape_after_ok(src: const u8[:], e: i64, row: i64) -> bool {
    if e >= src.len { return true; }
    if row == 3 || row == 4 { return !shape_body(src[e]); }
    if row >= 5 { return true; }
    if shape_alnum(src[e]) { return false; }
    return !(row == 2 && src[e] == 95);
}

// rule_shapes scans one file and adds the findings of the four rules to
// out. It gives the count it added. The count stops at MAX_FILE_MATCHES.
fn rule_shapes(src: const u8[:], file_idx: i64, out: Finding[>..]&) -> i64 {
    shape_ensure();
    nl_build(src);
    var found: i64 = 0;
    var row: i64 = 0;
    for re in shape_re {
        var rx = re;
        let skip = if row == 5 { 0 } else { 1 };
        let this_row = row;
        let idx = shape_rule[shape_owner(row)];
        regex::each_match(rx, src) { s, e =>
            if found < MAX_FILE_MATCHES && shape_after_ok(src, e, this_row) {
                let line, col = nl_pos(s + skip);
                rep(out, idx, file_idx, line, col, reg_msg_s[idx]);
                found = found + 1;
            }
        };
        row = row + 1;
    }
    return found + shape_head(src, file_idx, out, found);
}

// shape_head finds a shape at byte 0 of the file. A shape at byte 0 has
// no byte before it, so the rows with a boundary byte cannot match it.
// The scan copies the first 128 bytes after one newline and keeps a
// match that starts at offset 0. The longest shape is 93 bytes.
fn shape_head(src: const u8[:], file_idx: i64, out: Finding[>..]&, before: i64) -> i64 {
    if src.len == 0 { return 0; }
    var head: u8[>..] = [];
    head.push(10);
    var i: i64 = 0;
    while i < src.len && i < 128 { head.push(src[i]); i = i + 1; }
    var found: i64 = 0;
    var row: i64 = 0;
    for re in shape_re {
        if row < 5 {
            var rx = re;
            let this_row = row;
            let idx = shape_rule[shape_owner(row)];
            regex::each_match(rx, head[..]) { s, e =>
                if s == 0 && before + found < MAX_FILE_MATCHES
                    && shape_after_ok(src, e - 1, this_row) {
                    let line, col = nl_pos(0);
                    rep(out, idx, file_idx, line, col, reg_msg_s[idx]);
                    found = found + 1;
                }
            };
        }
        row = row + 1;
    }
    return found;
}
