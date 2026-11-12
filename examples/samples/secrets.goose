// A sample file for the rule files. Every secret here is fake.
let api_secret = "not-a-real-value";
let private_key = "not-a-real-key";
let host = "10.20.30.40";
let owner = "dev@example.com";
let url = "http://internal.example.com/api";
// TODO(security) rotate the key
// FIXME the retry loop never stops
// the password is in the vault
// HACK until the fix ships
legacy_login(user, pass);
let debug_mode = true;
unsafe_copy(a, b);
sleep_ms(500);
