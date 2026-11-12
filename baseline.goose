// The baseline: the fingerprint of a finding and the set of a past
// run. A fingerprint is 48 bytes of lowercase hexadecimal: the hash of
// the rule ID, the hash of the path and the hash of the line text. The
// hash is FNV-1a 64. It is stable across runs and it is not a
// cryptographic claim.
namespace sast;

// fnv64 gives the FNV-1a 64 hash of the bytes.
fn fnv64(s: const u8[:]) -> u64 {
    var h: u64 = 14695981039346656037;
    for b in s {
        h = h ^ b;
        h = h * 1099511628211;
    }
    return h;
}

// hex64 writes the 16 lowercase hex bytes of the hash v.
fn hex64(v: u64, out: u8[>..]&) {
    format_uint(out, v, 16, 16, 48);
}

// The hash of each rule ID. The list grows with the registry.
var rule_hash_s: u64[>..] = [];

// rule_hash gives the hash of the rule ID at the index i.
fn rule_hash(i: i64) -> u64 {
    while rule_hash_s.len <= i { rule_hash_s.push(0); }
    if rule_hash_s[i] == 0 {
        rule_hash_s[i] = fnv64(reg_id_s[i]);
    }
    return rule_hash_s[i];
}

// fingerprint appends the 48 hex bytes of a finding: rule, path, line.
fn fingerprint(rule_id: const u8[:], path: const u8[:],
               line_text: const u8[:], out: u8[>..]&) {
    fingerprint_hashes(fnv64(rule_id), fnv64(path), fnv64(line_text), out);
}

// fingerprint_hashes appends the 48 hex bytes of a finding from the
// three hashes. A run hashes the path of a file once and the rule ID
// of a rule once.
fn fingerprint_hashes(rule_hash: u64, path_hash: u64, line_hash: u64,
                      out: u8[>..]&) {
    hex64(rule_hash, out);
    hex64(path_hash, out);
    hex64(line_hash, out);
}

// fp_of gives the fingerprint text of a finding from its two offsets.
fn fp_of(f: Finding) -> const u8[:] {
    return buf_texts[f.fp..f.fp_end];
}

// cmp_bytes gives -1, 0 or 1 as a is less than, equal to or greater
// than b.
fn cmp_bytes(a: const u8[:], b: const u8[:]) -> i64 {
    return compare(a, b);
}

// The baseline set of the run. The bytes of the fingerprints live in
// one buffer and the two offset lists hold the range of each row.
// The list base_idx holds the rows in sorted order.
var base_buf: u8[>..] = [];
var base_at: i64[>..] = [];
var base_idx: i64[>..] = [];

// base_row gives the bytes of the row i. Every row is 48 bytes.
fn base_row(i: i64) -> const u8[:] {
    let at = base_at[i];
    return base_buf[at..at + 48];
}

// is_fp reports whether the text is a fingerprint: 48 bytes of
// lowercase hexadecimal.
fn is_fp(s: const u8[:]) -> bool {
    if s.len != 48 { return false; }
    for b in s {
        if !((b >= 48 && b <= 57) || (b >= 97 && b <= 102)) { return false; }
    }
    return true;
}

// baseline_read parses the text of a baseline file into the set. A
// line that is not 48 bytes of lowercase hex is a fault that names
// the line number from 1. The bound is 65536 entries. A fault writes
// no byte of the file.
fn baseline_read(text: const u8[:], err: u8[>..]&) -> bool {
    var at: i64 = 0;
    var n: i64 = 1;
    var sorted = true;
    while at <= text.len {
        var e = at;
        while e < text.len && text[e] != 10 { e = e + 1; }
        let line = text[at..e];
        if line.len > 0 || e < text.len {
            if !is_fp(line) {
                format(err, "baseline line ", n, " is not a fingerprint");
                return false;
            }
            if base_idx.len >= 65536 {
                format(err, "the baseline has too many entries (the bound is 65536)");
                return false;
            }
            if base_idx.len > 0 && cmp_bytes(base_row(base_idx.len - 1), line) > 0 {
                sorted = false;
            }
            base_at.push(base_buf.len);
            var i: i64 = 0;
            while i < 48 { base_buf.push(line[i]); i = i + 1; }
            base_idx.push(base_idx.len);
        }
        if e >= text.len { break; }
        at = e + 1;
        n = n + 1;
    }
    if !sorted { sort(base_idx[..]) { a, b => cmp_bytes(base_row(a), base_row(b)) < 0 }; }
    return true;
}

// baseline_has reports whether the set of the run holds the
// fingerprint. The set is sorted, so the search is a binary search.
fn baseline_has(fp: const u8[:]) -> bool {
    var lo: i64 = 0;
    var hi: i64 = base_idx.len;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if cmp_bytes(base_row(base_idx[mid]), fp) < 0 { lo = mid + 1; } else { hi = mid; }
    }
    if lo >= base_idx.len { return false; }
    return cmp_bytes(base_row(base_idx[lo]), fp) == 0;
}

// baseline_reset empties the set of the run.
fn baseline_reset() {
    base_buf.resize(0, 0);
    base_at.resize(0, 0);
    base_idx.resize(0, 0);
}

// baseline_filter leaves out each finding that the set of the run
// holds. The other findings stay in the list.
fn baseline_filter(fs: Finding[>..]&) {
    retain(fs) { f => !baseline_has(fp_of(f)) };
}

// baseline_write appends the fingerprints of the findings to out,
// sorted and deduplicated, one per line.
fn baseline_write(fs: const Finding[:], out: u8[>..]&) {
    var rows: i64[>..] = [];
    var i: i64 = 0;
    while i < fs.len { rows.push(i); i = i + 1; }
    sort(rows[..]) { a, b => cmp_bytes(fp_of(fs[a]), fp_of(fs[b])) < 0 };
    var last: const u8[:] = "";
    for r in rows {
        let fp = fp_of(fs[r]);
        if cmp_bytes(fp, last) != 0 {
            var k: i64 = 0;
            while k < fp.len { out.push(fp[k]); k = k + 1; }
            out.push(10);
            last = fp;
        }
    }
}
