// Scans one source text and prints the findings.
import std;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

fn main() {
    var o = sast::default_options();
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    let src = "let password = \"hunter2hunter2\";\nlet r = rand_int(10);\n";
    sast::scan_text("src/main.goose", src, o, fs);
    var out: u8[>..] = [];
    sast::format_text(fs[..], out);
    sast::format_summary(fs.len, 1, 0, out);
    print(out[..]);
}
