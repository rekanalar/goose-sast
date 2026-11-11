// Loads the custom rules of the examples and scans one text with them.
import std;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

fn main() {
    var rules: u8[>..] = [];
    read_file("examples/custom-rules.json", rules);
    var err: u8[>..] = [];
    if !sast::read_custom(rules[..], err) {
        print("the rules do not parse: ", err[..], "\n");
        return;
    }
    var o = sast::default_options();
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    let src = "let debug_mode = true;\nlegacy_login(user, pass);\n";
    sast::scan_text("src/app.goose", src, o, fs);
    var out: u8[>..] = [];
    sast::format_text(fs[..], out);
    print(out[..]);
}
