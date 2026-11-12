// Shows the next-line directive, the report of an unused suppression and
// a regex rule.
import std;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

fn main() {
    // The directive on the first line silences the weak hash below it.
    // The comment on the third line matches nothing.
    let src = "// nosec:next G401\nlet h = md5(data);\nlet a = 1; // nosec G404\nlet t = \"TODO(jim)\"; // TODO(ann)\n";
    var rules: u8[>..] = [];
    for c in "{\"rules\":[{\"id\":\"HOUSE03\",\"severity\":\"low\",\"kind\":\"regex\",\"text\":\"TODO\\\\([a-z]+\\\\)\",\"message\":\"a todo with an owner\"}]}" { rules.push(c); }
    var err: u8[>..] = [];
    if !sast::read_custom(rules[..], err) { print("rule file: ", err[..]); return; }
    var o = sast::default_options();
    o.report_unused = true;
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    sast::scan_text("src/main.goose", src, o, fs);
    var out: u8[>..] = [];
    sast::format_text(fs[..], out);
    print(out[..]);
    print(sast::unused_text[..]);
    sast::custom_reset();
}
