// The output of a run. The text form holds one line per finding. The
// bytes of a path or a message outside printable ASCII appear as a
// \xNN escape, so a line never breaks the layout.
namespace sast;

import json;

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
// files that the walk skipped. The clause of the left-out directories
// appears only when the profile left one out. The clause holds a count
// and a flag name, so no path reaches the terminal.
fn format_summary(findings: i64, scanned: i64, skipped: i64, out: u8[>..]&) {
    format(out, "sast: ", findings, " finding(s), ", scanned, " file(s) scanned, ",
           skipped, " file(s) skipped");
    if dirs_left_out > 0 {
        format(out, ", ", dirs_left_out,
               " director(ies) left out by the profile, use -profile all");
    }
    out.push(10);
}

// json_text writes s as a JSON string. A byte outside printable ASCII
// first becomes a \xNN escape, so the output is valid UTF-8 and holds
// no control byte.
fn json_text(out: u8[>..]&, s: const u8[:]) {
    var safe: u8[>..] = [];
    put_escaped(safe, s);
    json::format_string(out, safe[..]);
}

// format_json writes one JSON object: the findings, the totals per
// severity, the count of scanned files and the count of skipped files.
fn format_json(fs: const Finding[:], scanned: i64, skipped: i64, out: u8[>..]&) {
    reg_ensure();
    var by_sev: i64[5] = [0, 0, 0, 0, 0];
    out.push(123);
    json::format_key(out, "findings");
    out.push(91);
    var i: i64 = 0;
    while i < fs.len {
        let f = fs[i];
        if i > 0 { out.push(44); }
        if f.sev >= 1 && f.sev <= 4 { by_sev[f.sev] = by_sev[f.sev] + 1; }
        out.push(123);
        json::format_key(out, "rule"); json_text(out, reg_id_s[f.rule]); out.push(44);
        json::format_key(out, "severity"); json_text(out, sev_name(f.sev)); out.push(44);
        json::format_key(out, "confidence"); json_text(out, conf_name(f.conf)); out.push(44);
        json::format_key(out, "cwe"); json::format_int(out, f.cwe); out.push(44);
        json::format_key(out, "file"); json_text(out, path_of(f.file)); out.push(44);
        json::format_key(out, "line"); json::format_int(out, f.line); out.push(44);
        json::format_key(out, "column"); json::format_int(out, f.col); out.push(44);
        json::format_key(out, "message"); json_text(out, msg_of(f));
        out.push(125);
        i = i + 1;
    }
    out.push(93);
    out.push(44);
    json::format_key(out, "totals");
    out.push(123);
    json::format_key(out, "low"); json::format_int(out, by_sev[1]); out.push(44);
    json::format_key(out, "medium"); json::format_int(out, by_sev[2]); out.push(44);
    json::format_key(out, "high"); json::format_int(out, by_sev[3]); out.push(44);
    json::format_key(out, "critical"); json::format_int(out, by_sev[4]);
    out.push(125);
    out.push(44);
    json::format_key(out, "scanned"); json::format_int(out, scanned); out.push(44);
    json::format_key(out, "skipped"); json::format_int(out, skipped); out.push(44);
    json::format_key(out, "left_out"); json::format_int(out, dirs_left_out);
    out.push(125);
    out.push(10);
}

// format_sarif writes one SARIF 2.1.0 object. A code scanning service
// reads it. The level maps from the severity: LOW is note, MEDIUM is
// warning, HIGH and CRITICAL are error. The version of the package
// sits in the driver.
fn format_sarif(fs: const Finding[:], out: u8[>..]&) {
    reg_ensure();
    out.append("{\"$schema\":\"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"goose-sast\",\"version\":\"");
    out.append(VERSION);
    out.append("\",\"rules\":[");
    var i: i64 = 0;
    while i < reg_id_s.len {
        if i > 0 { out.push(44); }
        out.append("{\"id\":");
        json_text(out, reg_id_s[i]);
        out.append(",\"shortDescription\":{\"text\":");
        json_text(out, reg_msg_s[i]);
        out.append("},\"fullDescription\":{\"text\":");
        json::format_string(out, doc_explain(i));
        out.append("},\"help\":{\"text\":");
        json::format_string(out, doc_fix(i));
        out.append("},\"properties\":{\"tags\":[\"security\"");
        if reg_cwe_s[i] > 0 {
            out.append(",\"external/cwe/cwe-");
            json::format_int(out, reg_cwe_s[i]);
            out.push(34);
        }
        out.append("]}}");
        i = i + 1;
    }
    out.append("]}},\"results\":[");
    i = 0;
    while i < fs.len {
        let f = fs[i];
        if i > 0 { out.push(44); }
        out.append("{\"ruleId\":");
        json_text(out, reg_id_s[f.rule]);
        out.append(",\"level\":");
        // The level maps from the severity.
        var lvl: const u8[:] = "warning";
        if f.sev <= SEV_LOW { lvl = "note"; }
        else if f.sev >= SEV_HIGH { lvl = "error"; }
        json_text(out, lvl);
        out.append(",\"message\":{\"text\":");
        json_text(out, msg_of(f));
        out.append("},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
        json_text(out, path_of(f.file));
        out.append("},\"region\":{\"startLine\":");
        json::format_int(out, f.line);
        out.append(",\"startColumn\":");
        json::format_int(out, f.col);
        out.append("}}}]}");
        i = i + 1;
    }
    out.append("]}]}");
    out.push(10);
}
