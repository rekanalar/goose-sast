// Reads the settings of a run from a config file and scans two paths.
//
// The config file of the example holds the settings that a run uses.
// The program reads the text of the file and gives it to the reader of
// the package. The program then scans two texts and prints the
// findings of both.
import std;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

fn main() {
    // The text of a config file. A file of the current directory with
    // the name .goose-sast.json is read when no flag names another.
    var text: u8[>..] = [];
    for c in "{\n  \"min_severity\": \"medium\",\n  \"min_confidence\": \"low\",\n  \"exclude\": \"G401\",\n  \"max_files\": 512,\n  \"max_depth\": 32\n}\n" {
        text.push(c);
    }

    // The reader fills the options of the run. The bits of the mask
    // hold the settings that the command line set. Those settings
    // keep their value.
    var o = sast::default_options();
    var policy: u8[>..] = [];
    var advisories: u8[>..] = [];
    var rules: u8[>..] = [];
    var err: u8[>..] = [];
    if !sast::read_config(text[..], 0, o, policy, advisories, rules, err) {
        print(err[..]);
        exit(2);
    }

    // The run scans the targets in turn.
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    let first = "let password = \"hunter2hunter2\";\n";
    let second = "let h = md5(data);\n";
    sast::scan_text("src/one.goose", first, o, fs);
    sast::scan_text("src/two.goose", second, o, fs);
    sast::sort_findings(fs);
    var out: u8[>..] = [];
    sast::format_text(fs[..], out);
    sast::format_summary(fs.len, 2, 0, out);
    print(out[..]);
}
