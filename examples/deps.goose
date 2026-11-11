// Reads the import lines of a file and runs the dependency checks
// against a policy and an advisory file.
import std;
import sast from "..";
import semver from "rekanalar/goose-semver@v1.0.1";

fn main() {
    var root: u8[>..] = [];
    read_file("examples/policy/root.goose", root);
    var pol: u8[>..] = [];
    read_file("examples/policy/policy.json", pol);
    var perr: u8[>..] = [];
    if !sast::read_policy(pol[..], perr) {
        print("the policy does not parse: ", perr[..], "\n");
        return;
    }
    var adv: u8[>..] = [];
    read_file("examples/policy/advisories.json", adv);
    var aerr: u8[>..] = [];
    if !sast::read_advisories(adv[..], aerr) {
        print("the advisory file does not parse: ", aerr[..], "\n");
        return;
    }
    var fs: sast::Finding[>..] = [];
    sast::findings_reset();
    let n = sast::check_deps(root[..], fs);
    var out: u8[>..] = [];
    sast::format_text(fs[..], out);
    print(out[..]);
    print("sast: ", n, " dependency finding(s)\n");
}
