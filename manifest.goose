// The manifest reader: it reads the import lines of a program. Each
// import line names the package, the source and the pinned tag.
namespace sast;

// The dependencies of the last read. The bytes live in one buffer; the
// offset lists hold the range of each field of each dependency.
var dep_buf: u8[>..] = [];
var dep_name_at: i64[>..] = [];
var dep_name_end: i64[>..] = [];
var dep_src_at: i64[>..] = [];
var dep_src_end: i64[>..] = [];
var dep_tag_at: i64[>..] = [];
var dep_tag_end: i64[>..] = [];
var dep_line: i64[>..] = [];

// dep_reset empties the dependency list.
fn dep_reset() {
    dep_buf.resize(0, 0);
    dep_name_at.resize(0, 0);
    dep_name_end.resize(0, 0);
    dep_src_at.resize(0, 0);
    dep_src_end.resize(0, 0);
    dep_tag_at.resize(0, 0);
    dep_tag_end.resize(0, 0);
    dep_line.resize(0, 0);
}

// dep_push copies one field into the dependency buffer and gives its
// range.
fn dep_push(text: const u8[:]) -> i64, i64 {
    let at = dep_buf.len;
    for b in text { dep_buf.push(b); }
    return at, dep_buf.len;
}

// dep_name gives the bound name of the dependency i.
fn dep_name(i: i64) -> const u8[:] {
    return dep_buf[dep_name_at[i]..dep_name_end[i]];
}

// dep_source gives the source of the dependency i.
fn dep_source(i: i64) -> const u8[:] {
    return dep_buf[dep_src_at[i]..dep_src_end[i]];
}

// dep_tag gives the pinned tag of the dependency i.
fn dep_tag(i: i64) -> const u8[:] {
    return dep_buf[dep_tag_at[i]..dep_tag_end[i]];
}

// dep_line_of gives the line of the import of the dependency i.
fn dep_line_of(i: i64) -> i64 {
    return dep_line[i];
}

// dep_count gives the count of dependencies.
fn dep_count() -> i64 {
    return dep_name_at.len;
}

// split_at_at splits the text at the last @ sign. It gives the part
// before and the part after. A text with no @ sign gives the whole text
// and an empty part. The last sign counts, because a URL source can hold
// an @ in its user part.
fn split_at_at(text: const u8[:]) -> const u8[:], const u8[:] {
    var i: i64 = text.len - 1;
    while i >= 0 {
        if text[i] == 64 {
            return text[0..i], text[i + 1..text.len];
        }
        i = i - 1;
    }
    return text, "";
}

// read_manifest reads the import lines of the source. An import line
// holds the name, the word from and a string with the source and the
// tag. A line with no @ sign gives a dependency with an empty tag. A
// line with no string is not a dependency. It gives the count.
fn read_manifest(src: const u8[:]) -> i64 {
    dep_reset();
    var line: i64 = 1;
    var i: i64 = 0;
    while i < src.len {
        // Read the line.
        let start = i;
        while i < src.len && src[i] != 10 { i = i + 1; }
        let text = src[start..i];
        if i < src.len { i = i + 1; }
        // The line starts with the word import.
        if text.len > 7 && text[0..6] == "import" && (text[6] == 32 || text[6] == 9) {
            var k: i64 = 7;
            // The bound name.
            while k < text.len && text[k] != 32 && text[k] != 9 { k = k + 1; }
            let name = text[7..k];
            // The word from.
            while k < text.len && (text[k] == 32 || text[k] == 9) { k = k + 1; }
            if k + 4 <= text.len && text[k..k + 4] == "from" {
                k = k + 4;
                while k < text.len && (text[k] == 32 || text[k] == 9) { k = k + 1; }
                if k < text.len && text[k] == 34 {
                    // The string ends at the closing quote.
                    var e = k + 1;
                    while e < text.len && text[e] != 34 { e = e + 1; }
                    if e < text.len {
                        let lit = text[k + 1..e];
                        let src_part, tag_part = split_at_at(lit);
                        let na, nb = dep_push(name);
                        dep_name_at.push(na);
                        dep_name_end.push(nb);
                        let sa, sb = dep_push(src_part);
                        dep_src_at.push(sa);
                        dep_src_end.push(sb);
                        let ta, tb = dep_push(tag_part);
                        dep_tag_at.push(ta);
                        dep_tag_end.push(tb);
                        dep_line.push(line);
                    }
                }
            }
        }
        line = line + 1;
    }
    return dep_count();
}
