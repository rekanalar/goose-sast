// The output of a run. The text form holds one line per finding. The
// bytes of a path or a message outside printable ASCII appear as a
// \xNN escape, so a line never breaks the layout.
namespace sast;

// sev_name gives the name of a severity.
fn sev_name(sev: i64) -> const u8[:] {
    if sev >= SEV_CRITICAL { return "critical"; }
    if sev == SEV_HIGH { return "high"; }
    if sev == SEV_MEDIUM { return "medium"; }
    return "low";
}

// conf_name gives the name of a confidence.
fn conf_name(conf: i64) -> const u8[:] {
    if conf >= CONF_HIGH { return "high"; }
    if conf == CONF_MEDIUM { return "medium"; }
    return "low";
}

// put_escaped writes the bytes of s to out. A byte outside the
// printable ASCII appears as a \xNN escape.
fn put_escaped(out: u8[>..]&, s: const u8[:]) {
    let digits = "0123456789abcdef";
    var i: i64 = 0;
    while i < s.len {
        let b = s[i];
        if b < 32 || b > 126 {
            out.push(92);
            out.push(120);
            out.push(digits[(b >> 4) as i64]);
            out.push(digits[(b & 15) as i64]);
        } else {
            out.push(b);
        }
        i = i + 1;
    }
}

// format_text writes one line per finding. The line holds the path,
// the line, the column, the severity, the rule ID and the message.
fn format_text(fs: const Finding[:], out: u8[>..]&) {
    reg_ensure();
    var i: i64 = 0;
    while i < fs.len {
        let f = fs[i];
        put_escaped(out, path_of(f.file));
        out.push(58);
        format(out, f.line, ":", f.col, ": ", sev_name(f.sev), ": ",
               reg_id_s[f.rule], ": ");
        put_escaped(out, msg_of(f));
        out.push(10);
        i = i + 1;
    }
}

// format_summary writes the count line of a run. It holds the count of
// the findings, the count of the scanned files and the count of the
// files that the walk skipped.
fn format_summary(findings: i64, scanned: i64, skipped: i64, out: u8[>..]&) {
    format(out, "sast: ", findings, " finding(s), ", scanned, " file(s) scanned, ",
           skipped, " file(s) skipped\n");
}
