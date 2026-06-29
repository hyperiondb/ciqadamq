#![no_main]
// db.rs is included whole via #[path]; only its pure auth fns are exercised here.
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[path = "../../src/db.rs"]
mod db;

#[derive(Arbitrary, Debug)]
struct Input {
    stored_hash: String,
    pepper: Vec<u8>,
    username: String,
    password: String,
    stored: Vec<u8>,
}

fuzz_target!(|i: Input| {
    // argon2 PHC parser must not panic on a malformed stored hash.
    let _ = db::verify_password(&i.stored_hash, &i.password);

    // The fast HMAC verifier must never panic, and a freshly computed verifier
    // must verify against itself.
    let v = db::compute_verifier(&i.pepper, &i.username, &i.password);
    assert!(db::verify_fast(&i.pepper, &i.username, &i.password, &v));
    let _ = db::verify_fast(&i.pepper, &i.username, &i.password, &i.stored);
});
