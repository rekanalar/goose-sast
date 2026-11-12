// The taint rules: a value from an outside source reaches a process call
// or a file path. The taint map holds the names that carry such a
// value, and the scope where each name was bound.
namespace sast;

// The taint map of the last file. Each entry holds a name and the
// scope that bound it.
var taint_at: i64[>..] = [];
var taint_end: i64[>..] = [];
var taint_scope: i64[>..] = [];
var taint_buf: u8[>..] = [];

// taint_reset empties the taint map.
fn taint_reset() {
    taint_at.resize(0, 0);
    taint_end.resize(0, 0);
    taint_scope.resize(0, 0);
    taint_buf.resize(0, 0);
}

// taint_push records that the name holds a value from a source, in the
// given scope.
fn taint_push(name: const u8[:], scope: i64) {
    taint_at.push(taint_buf.len);
    for b in name { taint_buf.push(b); }
    taint_end.push(taint_buf.len);
    taint_scope.push(scope);
}

// taint_name gives the name of the taint entry i.
fn taint_name(i: i64) -> const u8[:] {
    return taint_buf[taint_at[i]..taint_end[i]];
}

// taint_live reports whether the name holds a tainted value in the
// scope. A binding counts when its scope is the scope or holds it, so
// a name of a sibling scope never reaches the use.
fn taint_live(name: const u8[:], scope: i64) -> bool {
    var i: i64 = 0;
    while i < taint_at.len {
        if taint_name(i) == name && scope_sees(taint_scope[i], scope) {
            return true;
        }
        i = i + 1;
    }
    return false;
}

// is_source_call reports whether the name is a source of outside data.
// The command line, the environment and a file read all carry data that
// a caller controls.
fn is_source_call(name: const u8[:]) -> bool {
    return name == "args" || name == "getenv" || name == "read_file"
        || name == "read_stdin" || name == "read_line";
}

// is_taint_sink reports whether the name is a sink for outside data.
fn is_taint_sink(name: const u8[:]) -> bool {
    return name == "run" || name == "spawn" || name == "write_file"
        || name == "append_file" || name == "delete_file"
        || name == "rename_file" || name == "make_dir";
}

// rule_taint runs G702 and G703: a value from a source reaches a
// process call or a file path. The taint map holds the names that the
// source bound, and the scope that bound them.
fn rule_taint(src: const u8[:], file_idx: i64, out: Finding[>..]&) {
    taint_reset();
    let g702 = reg_find("G702");
    let g703 = reg_find("G703");
    var i: i64 = 0;
    while i < tk_count {
        if tk_kind[i] == TK_IDENT {
            let name = tok_of(src, i);
            // A call of a source: the value it returns is tainted.
            if is_source_call(name) && i + 1 < tk_count
                && tk_kind[i + 1] == TK_OTHER && tok_of(src, i + 1) == "(" {
                // The name that takes the value is the identifier
                // before the call, as in `let x = args();`.
                var j = i - 1;
                while j >= 0 && tk_line[j] >= tk_line[i] - 3 {
                    if tk_kind[j] == TK_IDENT && j + 1 < tk_count
                        && tk_kind[j + 1] == TK_OTHER
                        && (tok_of(src, j + 1) == "="
                            || tok_of(src, j + 1) == ":") {
                        taint_push(tok_of(src, j), tk_scope[j]);
                        break;
                    }
                    j = j - 1;
                }
            }
            // A sink: a tainted name among the arguments.
            if is_taint_sink(name) && i + 1 < tk_count
                && tk_kind[i + 1] == TK_OTHER && tok_of(src, i + 1) == "(" {
                var k = i + 2;
                var scope = tk_scope[i];
                while k < tk_count && tk_line[k] <= tk_line[i] + 4 {
                    if tk_kind[k] == TK_IDENT && taint_live(tok_of(src, k), scope) {
                        var rule = g703;
                        if name == "run" || name == "spawn" { rule = g702; }
                        rep(out, rule, file_idx, tk_line[i],
                            tok_col_of(src, tk_start[i]),
                            "a value from an outside source reaches this call");
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
