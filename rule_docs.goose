// The documentation of each built-in rule: an explanation, a flagged
// example, a clean example and a fix hint. The text is English and it
// is constant. The program reads no part of it from a file.
//
// A rule that reads a policy or an advisory file shows the text of that
// file as its example. A rule with no detector in this release says so
// in its explanation. The examples of S101 to S104 hold placeholders,
// and doc_fixture builds the scanned text from pieces at run time.
namespace sast;

import json;

var doc_loaded: bool = false;
var doc_explain_s: const u8[:][>..] = [];
var doc_flagged_s: const u8[:][>..] = [];
var doc_clean_s: const u8[:][>..] = [];
var doc_fix_s: const u8[:][>..] = [];
var doc_exempt_s: bool[>..] = [];
var doc_reason_s: const u8[:][>..] = [];

// doc_put stores the text of the rule with that ID. A rule that the
// registry does not hold is a fault of the program.
fn doc_put(id: const u8[:], ex: const u8[:], fl: const u8[:],
           cl: const u8[:], fx: const u8[:]) {
    let i = reg_find(id);
    if i < 0 { abort("the documentation names a rule that does not exist"); }
    doc_explain_s[i] = ex;
    doc_flagged_s[i] = fl;
    doc_clean_s[i] = cl;
    doc_fix_s[i] = fx;
}

// doc_exempt marks the rule with that ID as one without a scanned
// example. It gives the reason.
fn doc_exempt(id: const u8[:], reason: const u8[:]) {
    let i = reg_find(id);
    if i < 0 { abort("the documentation names a rule that does not exist"); }
    doc_exempt_s[i] = true;
    doc_reason_s[i] = reason;
}

// doc_is_exempt reports whether the rule at the registry index i has
// no scanned example.
fn doc_is_exempt(i: i64) -> bool { docs_ensure(); return doc_exempt_s[i]; }

// doc_reason gives the reason that the rule at the registry index i
// has no scanned example.
fn doc_reason(i: i64) -> const u8[:] { docs_ensure(); return doc_reason_s[i]; }

// docs_ensure fills the four lists once, in the order of the registry.
fn docs_ensure() {
    if doc_loaded { return; }
    reg_ensure();
    var n: i64 = 0;
    while n < reg_id_s.len {
        doc_explain_s.push("");
        doc_flagged_s.push("");
        doc_clean_s.push("");
        doc_fix_s.push("");
        doc_exempt_s.push(false);
        doc_reason_s.push("");
        n = n + 1;
    }
    doc_put("G101", "A password or token in the source reaches everyone who can read the file. The file goes to version control and to backups. Removing the value later does not remove it from the history. The rule looks at names such as password and token that get a string literal.",
            "let password = \"hunter2hunter2\";",
            "let password = read_secret(key);",
            "Read the secret from the environment or from a secret store at run time. Rotate any secret that was in the source.");
    doc_put("G102", "A service that binds to all interfaces accepts connections from every network that reaches the host. A local tool then becomes a remote target. The rule flags the wildcard addresses in a listen or serve call.",
            "listen(\"0.0.0.0\", port);",
            "listen(\"127.0.0.1\", port);",
            "Bind to the loopback address unless the service must serve other hosts. Put a firewall in front of a public bind.");
    doc_put("G109", "A cast to a smaller integer type drops the high bits without a warning. A length or an index that wraps can pass a size check and then overflow a buffer. The rule flags the forced narrowing cast.",
            "let c = x as! i8;",
            "let c = checked_narrow(x);",
            "Check the range of the value before the cast. Use a checked conversion that fails when the value does not fit.");
    doc_put("G116", "A bidirectional control character changes the order in which an editor shows the text. Code can then look different from what the compiler reads. This is the trojan source attack. The rule flags these characters in the source.",
            "let a = \"<U+202E>\";",
            "let a = \"plain text\";",
            "Remove the control character from the source. Write the character as an escape if the program needs it.");
    doc_put("G201", "A SQL text that the program builds with a format call takes the values as part of the query. A value that holds quote characters then changes the meaning of the query. This is SQL injection.",
            "let q = \"select \" + str(x);",
            "let q = query(\"select * from t where id = ?\", x);",
            "Pass the values as bound parameters. Keep the query text constant.");
    doc_put("G202", "A SQL text that the program builds by concatenation takes the values as part of the query. A value with quote characters changes the meaning of the query. This is SQL injection.",
            "let q = \"select * from t where a=\" + x;",
            "let q = query(\"select * from t where a = ?\", x);",
            "Pass the values as bound parameters. Keep the query text constant.");
    doc_put("G203", "HTML that the program builds from a variable carries the bytes of the variable into the page. A value with markup then runs as script in the browser. This is cross-site scripting. The confidence of the rule is low, because the value may be safe.",
            "let h = \"<b>\" + name;",
            "let h = html_escape(name);",
            "Escape every value for the HTML context before it joins the markup. Use a template that escapes by default.");
    doc_put("G204", "A command that comes from a variable lets the source of the variable choose the program to run. A value from outside then runs any program. This is command injection.",
            "run(cmd, args);",
            "run(\"/bin/ls\", args);",
            "Use a fixed command name or pick the command from a fixed list. Pass the arguments as a list and not as one text.");
    doc_put("G301", "A directory with wide permissions lets other users on the host list, read or change its files. A shared host then leaks or loses data.",
            "make_dir(\"d\", 0o755);",
            "make_dir(\"d\", 0o600);",
            "Give the directory the narrowest mode that the program needs. Give access to the owner and to one group only.");
    doc_put("G302", "A file mode that is too wide lets other users read or change the file. A configuration file or a key file then leaks or gets replaced.",
            "f(0o777);",
            "f(0o600);",
            "Use mode 0o600 for a private file. Add group access only when a task needs it.");
    doc_put("G303", "A predictable path in the shared temp directory lets another user create the file first. That user can also replace it with a link. The program then reads or writes the data of that user.",
            "write_file(\"/tmp/x\", d);",
            "write_file(unique_name, d);",
            "Create the temp file with a random name and with exclusive create. Use a private directory.");
    doc_put("G304", "A file path from a variable may point outside the intended directory. A value such as a parent path segment then reads or writes any file that the process can reach. This is path traversal. The rule is in the strict profile, because most paths are safe.",
            "read_file(p, out);",
            "read_file(\"config.txt\");",
            "Reject paths that hold a parent segment or an absolute prefix. Join the value to a fixed base directory and check the result.");
    doc_put("G306", "A write that sets wide permissions on the new file lets other users read or change it. The data of the program then leaks or gets replaced.",
            "write_file(\"a\", d, 0o644);",
            "write_file(\"a\", d, 0o600);",
            "Create the file with mode 0o600 or tighter. Add access only when a task needs it.");
    doc_put("G401", "A weak hash such as md5 or sha1 has known collisions. An attacker can build two inputs with the same hash. The hash then fails as a check of integrity or of identity.",
            "let h = md5(x);",
            "let h = sha256(x);",
            "Use sha256 or a stronger hash. Use a password hash with a salt for passwords.");
    doc_put("G404", "A weak random source gives values that an attacker can predict. A token, a key or a nonce from such a source is guessable. The rule also flags a generator with a constant seed.",
            "let r = rand_int(5);",
            "let r = secure_random_int(5);",
            "Use the random source of the operating system for secrets. Never seed a generator with a constant.");
    doc_put("G111", "A path that is the root directory makes the call act on the whole file system. A walk, a delete or a copy then reaches every file that the process can access.",
            "read_file(\"/\", out);",
            "read_file(\"data/in.txt\", out);",
            "Name the exact path that the call needs. Check that a computed path is not the root.");
    doc_put("B101", "An assert may be removed in a release build. A check that guards a security decision then vanishes. The rule is in the strict profile, because many asserts only state an internal fact.",
            "assert(x > 0);",
            "if x <= 0 { abort(\"x must be positive\"); }",
            "Use a plain check with an error path for input and for security decisions. Keep assert for internal facts.");
    doc_put("B110", "A catch block that holds nothing hides every fault of the try body. The program goes on in a wrong state, and nobody sees why.",
            "exception::try<u8[]>(load) { };",
            "exception::try<u8[]>(load) { error => print(error); };",
            "Handle the fault, log it or pass it on. If the program must ignore it, write why in a comment.");
    doc_put("B113", "A wait with no time limit, or with a limit of zero, can block the program forever. A slow or hostile peer then holds the thread.",
            "let w = wait(h, 0);",
            "let w = wait(h, 5000);",
            "Give every wait a time limit in milliseconds. Handle the timeout case.");
    doc_put("B607", "A command with a partial path is found through the search path of the environment. An attacker who controls that path runs another program with the same name.",
            "run(\"ls\", args);",
            "run(\"/bin/ls\", args);",
            "Use the full path of the program. Do not rely on the search path.");
    doc_put("B609", "A wildcard in a command argument expands to the file names in the directory. A file with a name such as an option then changes what the command does.",
            "run(\"/bin/tar\", \"*\");",
            "run(\"/bin/tar\", \"a.txt\");",
            "Pass an explicit list of file names. Put a double hyphen before names that may start with a hyphen.");
    doc_put("G501", "The md5 hash has known collisions. An attacker can build two inputs with the same md5 value. Do not use it for integrity, identity or passwords.",
            "import m from \"a/goose-md5@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use sha256 or a stronger hash package.");
    doc_put("G502", "The des cipher has a key of 56 bits. A brute force search breaks it. Data that it protects is open to an attacker with modest means.",
            "import m from \"a/goose-des@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use an AES package with a modern mode.");
    doc_put("G503", "The rc4 cipher has biases in its output stream. Attacks recover the plain text from enough cipher text. Protocols have dropped it.",
            "import m from \"a/goose-rc4@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use an AES package or a stream cipher with authentication.");
    doc_put("G504", "The cgi interface starts a process for each request and passes the request in the environment. Handlers often trust these values. This leads to injection faults.",
            "import m from \"a/goose-cgi@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use a package that reads the request through a safe interface.");
    doc_put("G505", "The sha1 hash has practical collision attacks. A signature or a check that relies on it can be forged. Do not use it for integrity or identity.",
            "import m from \"a/goose-sha1@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use sha256 or a stronger hash package.");
    doc_put("G506", "The md4 hash is broken. An attacker finds collisions in seconds on a normal computer. Do not use it for any security purpose.",
            "import m from \"a/goose-md4@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use sha256 or a stronger hash package.");
    doc_put("G507", "The ripemd160 hash has a digest of 160 bits. This size gives a low margin against collision search. Newer hashes give a larger margin.",
            "import m from \"a/goose-ripemd160@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use sha256 or a stronger hash package.");
    doc_put("B401", "The telnet protocol sends text, passwords included, with no encryption. Anyone on the path reads and changes the session.",
            "import m from \"a/goose-telnet@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use an ssh package and keep the session encrypted.");
    doc_put("B402", "The ftp protocol sends text, passwords included, with no encryption. Anyone on the path reads and changes the transfer.",
            "import m from \"a/goose-ftp@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use sftp or https and keep the transfer encrypted.");
    doc_put("B403", "A pickle stream can build any object and run code when a program loads it. A stream from an untrusted source runs the code of an attacker.",
            "import m from \"a/goose-pickle@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use a data format that holds no code, such as json.");
    doc_put("B404", "A package that starts processes is a risk when it gets input from outside. This import marks the file for a closer review of the calls.",
            "import m from \"a/goose-process@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Check every call to the package for fixed commands and escaped arguments.");
    doc_put("B410", "The lxml reader can load external entities. A document from an attacker then reads local files or calls other hosts. This is the xxe attack.",
            "import m from \"a/goose-lxml@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Turn off the loading of external entities and of network access.");
    doc_put("B411", "An xmlrpc server decodes a document from the peer. A crafted document can exhaust memory or load external entities.",
            "import m from \"a/goose-xmlrpc@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use a protocol with a typed, bounded decoder.");
    doc_put("B405", "An xml reader may load external entities and expand entities without a limit. A document from an attacker then reads files or exhausts memory. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-xml@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Turn off external entities and limit the expansion of entities.");
    doc_put("B406", "A sax reader may load external entities and expand entities without a limit. A document from an attacker then reads files or exhausts memory. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-xmlsax@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Turn off external entities and limit the expansion of entities.");
    doc_put("B407", "A dom builder may load external entities and expand entities without a limit. A document from an attacker then reads files or exhausts memory. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-xmldom@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Turn off external entities and limit the expansion of entities.");
    doc_put("B408", "A minidom reader may load external entities and expand entities without a limit. A document from an attacker then reads files or exhausts memory. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-minidom@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Turn off external entities and limit the expansion of entities.");
    doc_put("B409", "A pulldom reader may load external entities and expand entities without a limit. A document from an attacker then reads files or exhausts memory. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-pulldom@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Turn off external entities and limit the expansion of entities.");
    doc_put("B412", "A cgi handler passes request values through the environment. Handlers often trust these values, and an attacker sets them. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-httpcgi@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use a handler that reads the request through a safe interface.");
    doc_put("B413", "An old crypto cipher library holds weak ciphers and has had no security fixes for years. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-crypto@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Use a maintained library with authenticated encryption.");
    doc_put("B414", "A cryptography module is a risk when a program uses it with weak choices. This import marks the file for review. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-cryptography@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Check the algorithms, the modes and the key sizes in the file.");
    doc_put("B415", "A bridge to a web application server often runs with the proxy variables of the request. An attacker sets these variables and changes the program. This release has no detector for this rule, so it reports nothing.",
            "import m from \"a/goose-wsgiref@v1.0.0\";",
            "import m from \"a/goose-sha256@v1.0.0\";",
            "Do not trust the proxy variables of a request.");
    doc_put("G103", "An extern function calls code outside the type checker. The compiler cannot check the types or the bounds of the call. A wrong signature or a bad buffer size corrupts memory.",
            "extern \"c_fn\" fn f(x: i64);",
            "fn f(x: i64) -> i64 { return x; }",
            "Keep the extern surface small and wrap each call in a checked function. Check every length before the call.");
    doc_put("G104", "A call whose result the program drops may hide a fault. A failed write or a failed check then goes on with no sign. The rule is in the strict profile, because many calls have a result that nobody needs.",
            "write_file(\"a\", d);",
            "let r = write_file(\"a\", d);",
            "Read the result and handle a failure. Name an unused result with an underscore, so the intent shows.");
    doc_put("G602", "An index into a fixed array that comes from a variable may lie outside the array. A read or a write beyond the end corrupts memory or leaks data. This release has no detector for this rule, so it reports nothing.",
            "let a: i64[4] = [0, 0, 0, 0];\nlet v = a[i];",
            "let a: i64[4] = [0, 0, 0, 0];\nlet v = a[i & 3];",
            "Check the index against the length before the access. Use a bounded loop.");
    doc_put("G702", "A value from an outside source, such as the arguments or the network, reaches a process call. An attacker then chooses the command or its arguments. This is command injection.",
            "let x = args();\nrun(\"/bin/ls\", x);",
            "let x = args();\nrun(\"/bin/ls\", \"-l\");",
            "Check the value against a fixed list before it reaches the call. Pass fixed arguments where you can.");
    doc_put("G703", "A value from an outside source, such as the arguments or the network, reaches a file path. An attacker then reads or writes any file that the process can reach. This is path traversal.",
            "let x = args();\nwrite_file(x, d);",
            "let x = args();\nwrite_file(\"out/a.txt\", d);",
            "Join the value to a fixed base directory. Reject a parent segment and an absolute path.");
    doc_put("BAN", "The policy file lists dependencies that the project must not use. A listed package, or a version in a listed range, gives this finding. The check reads the dependency imports and the policy file.",
            "{\"bans\": {\"deny\": [\"badpkg\"]}}",
            "{\"bans\": {\"deny\": []}}",
            "Remove the dependency or move to a version that the policy allows. Change the policy only after a review.");
    doc_put("LICENSE", "The policy file lists the licences that the project allows. A dependency with another licence, or with none, gives this finding when the policy requires one.",
            "{\"licenses\": {\"allow\": [\"MIT\"], \"require\": true}}",
            "{\"licenses\": {\"allow\": [\"MIT\", \"BSD\"]}}",
            "Replace the dependency or ask the owner for a licence that the policy allows.");
    doc_put("SOURCE", "The policy file lists the organizations that may supply a dependency. A package from another source gives this finding. This stops a package that an unknown party publishes.",
            "{\"sources\": {\"allow\": [\"rekanalar\"]}}",
            "{\"sources\": {\"allow\": [\"rekanalar\", \"mylab\"]}}",
            "Use a package from an allowed source, or add the source to the policy after a review.");
    doc_put("ADVISORY", "The advisory file lists known faults of package versions. A dependency in an affected range gives this finding. A known fault is easy for an attacker to use.",
            "{\"advisories\": [{\"id\": \"X-1\", \"package\": \"url\", \"versions\": \"<2.0.0\"}]}",
            "{\"advisories\": []}",
            "Move to the patched version that the advisory names. Check the advisory for a workaround if none exists.");
    doc_put("G117", "A value with a secret-like name that goes into a JSON writer leaves the program in the output. The output then reaches logs, files or a network peer.",
            "json::format_string(out, api_token);",
            "json::format_string(out, user_name);",
            "Leave the secret out of the output. Write a masked value if the reader needs a sign.");
    doc_put("S101", "An AWS access key ID is in the source. The ID starts with AKIA, ASIA, ABIA or ACCA, and 16 more capital letters or digits follow. Anyone who reads the file can use the key with its secret. The finding holds no byte of the match.",
            "let v = \"AKIA<16 capital letters>\";",
            "let v = load_secret(\"aws_key_id\");",
            "Revoke the key and create a new one. Load keys from a secret store at run time.");
    doc_put("S102", "A GitHub token is in the source. The token starts with a prefix such as ghp_ or github_pat_ and holds a long random body. Anyone who reads the file can act as the owner of the token. The finding holds no byte of the match.",
            "let v = \"ghp_<36 letters or digits>\";",
            "let v = load_secret(\"github_token\");",
            "Revoke the token on GitHub and create a new one. Load tokens from a secret store at run time.");
    doc_put("S103", "A Slack token is in the source. The token starts with xoxb-, xoxp- or a similar prefix, or with xapp-. Anyone who reads the file can use the Slack account of the token. The finding holds no byte of the match.",
            "let v = \"xoxb-<10 or more letters, digits or hyphens>\";",
            "let v = load_secret(\"slack_token\");",
            "Revoke the token in the Slack settings and create a new one. Load tokens from a secret store at run time.");
    doc_put("S104", "A private key header is in the source. The header names a private key, for example an RSA or an OpenSSH key. Anyone who reads the file can use the key. The finding holds no byte of the key.",
            "let v = \"-----BEGIN <type> PRIVATE KEY-----\";",
            "let v = read_key_file(path);",
            "Remove the key from the source and replace the key pair. Load keys from a file with tight permissions.");
    doc_put("PIN", "An import names a branch, so the code behind it changes when the owner moves the branch. With the commit rule on, a tag gives this finding too. An owner can move a tag. The next fetch can bring other code into the build.",
            "import url from \"rekanalar/goose-url@main\";",
            "import url from \"rekanalar/goose-url@3f2c1a9d4e5b\";",
            "Pin the import to a commit. Run goose fetch once and record the commit that you reviewed.");
    doc_put("CPART", "A fetched package holds a C part. Its build runs C code on the machine of the user. A package that the cache lacks also gives this finding, because the check cannot tell.",
            "{\"sources\": {\"report_c_parts\": true}}",
            "{\"sources\": {\"report_c_parts\": true, \"c_parts_allow\": [\"rekanalar/goose-curl\"]}}",
            "Read the C code of the package. Add the source to c_parts_allow when you accept it, or use a pure Goose package.");
    doc_exempt("BAN", "the rule reads a policy or an advisory file");
    doc_exempt("LICENSE", "the rule reads a policy or an advisory file");
    doc_exempt("SOURCE", "the rule reads a policy or an advisory file");
    doc_exempt("ADVISORY", "the rule reads a policy or an advisory file");
    doc_exempt("PIN", "the rule reads a policy or an advisory file");
    doc_exempt("CPART", "the rule reads a policy or an advisory file");
    doc_exempt("B405", "the release has no detector for the rule");
    doc_exempt("B406", "the release has no detector for the rule");
    doc_exempt("B407", "the release has no detector for the rule");
    doc_exempt("B408", "the release has no detector for the rule");
    doc_exempt("B409", "the release has no detector for the rule");
    doc_exempt("B412", "the release has no detector for the rule");
    doc_exempt("B413", "the release has no detector for the rule");
    doc_exempt("B414", "the release has no detector for the rule");
    doc_exempt("B415", "the release has no detector for the rule");
    doc_exempt("G602", "the release has no detector for the rule");
    doc_loaded = true;
}

// doc_explain gives the explanation of the rule at the registry index i.
fn doc_explain(i: i64) -> const u8[:] { docs_ensure(); return doc_explain_s[i]; }

// doc_flagged gives the flagged example of the rule at the index i.
fn doc_flagged(i: i64) -> const u8[:] { docs_ensure(); return doc_flagged_s[i]; }

// doc_clean gives the clean example of the rule at the index i.
fn doc_clean(i: i64) -> const u8[:] { docs_ensure(); return doc_clean_s[i]; }

// doc_fix gives the fix hint of the rule at the index i.
fn doc_fix(i: i64) -> const u8[:] { docs_ensure(); return doc_fix_s[i]; }

// doc_fixture writes the source text that a scan reads for the flagged
// example of the rule at the index i. It is the printed example for
// every rule but S101 to S104 and G116. These need real bytes that the
// printed text only names, so the function builds them from pieces.
fn doc_fixture(i: i64, out: u8[>..]&) {
    docs_ensure();
    let id = reg_id_s[i];
    if id == "S101" {
        for b in "let v = \"AK" { out.push(b); }
        for b in "IAABCDEFGHIJKLMNOP\";\n" { out.push(b); }
    } else if id == "S102" {
        for b in "let v = \"gh" { out.push(b); }
        for b in "p_" { out.push(b); }
        var k: i64 = 0;
        while k < 36 { out.push(97); k = k + 1; }
        for b in "\";\n" { out.push(b); }
    } else if id == "S103" {
        for b in "let v = \"xo" { out.push(b); }
        for b in "xb-1234567890\";\n" { out.push(b); }
    } else if id == "S104" {
        for b in "let v = \"-----BE" { out.push(b); }
        for b in "GIN RSA PRIVATE KEY-----\";\n" { out.push(b); }
    } else if id == "G116" {
        for b in "let a = \"\xE2\x80\xAE\";\n" { out.push(b); }
    } else {
        for b in doc_flagged_s[i] { out.push(b); }
        out.push(10);
    }
}

// explain_known gives the registry index of the rule with exactly that
// ID, or -1. An alias does not count, and an ID of more than 16 bytes
// is unknown.
fn explain_known(id: const u8[:]) -> i64 {
    reg_ensure();
    if id.len == 0 || id.len > 16 { return -1; }
    let i = reg_find(id);
    if i < 0 { return -1; }
    if reg_id_s[i] == id { return i; }
    return -1;
}

// put_lines writes the text with four spaces before each line.
fn put_lines(out: u8[>..]&, s: const u8[:]) {
    var start = true;
    for b in s {
        if start { out.append("    "); start = false; }
        out.push(b);
        if b == 10 { start = true; }
    }
    out.push(10);
}

// explain_rule writes the documentation of the rule with that ID as
// text or as one JSON object. It gives false when no built-in rule
// holds the ID, and it writes nothing then.
fn explain_rule(id: const u8[:], as_json: bool, out: u8[>..]&) -> bool {
    let i = explain_known(id);
    if i < 0 { return false; }
    docs_ensure();
    let prof = tier_name(reg_tier_s[i]);
    if as_json {
        out.push(123);
        json::format_key(out, "id"); json_text(out, reg_id_s[i]); out.push(44);
        json::format_key(out, "severity"); json_text(out, sev_name(reg_sev_s[i])); out.push(44);
        json::format_key(out, "confidence"); json_text(out, conf_name(reg_conf_s[i])); out.push(44);
        json::format_key(out, "cwe"); json::format_int(out, reg_cwe_s[i]); out.push(44);
        json::format_key(out, "profile"); json_text(out, prof); out.push(44);
        json::format_key(out, "explanation"); json::format_string(out, doc_explain_s[i]); out.push(44);
        json::format_key(out, "flagged"); json::format_string(out, doc_flagged_s[i]); out.push(44);
        json::format_key(out, "clean"); json::format_string(out, doc_clean_s[i]); out.push(44);
        json::format_key(out, "fix"); json::format_string(out, doc_fix_s[i]);
        out.push(125);
        out.push(10);
        return true;
    }
    format(out, "ID: ", reg_id_s[i], "\n");
    format(out, "Severity: ", sev_name(reg_sev_s[i]), "\n");
    format(out, "Confidence: ", conf_name(reg_conf_s[i]), "\n");
    if reg_cwe_s[i] > 0 { format(out, "CWE: ", reg_cwe_s[i], "\n"); }
    else { format(out, "CWE: none\n"); }
    format(out, "Profile: ", prof, "\n");
    format(out, "Explanation: ", doc_explain_s[i], "\n");
    format(out, "Flagged:\n");
    put_lines(out, doc_flagged_s[i]);
    format(out, "Clean:\n");
    put_lines(out, doc_clean_s[i]);
    format(out, "Fix: ", doc_fix_s[i], "\n");
    return true;
}
