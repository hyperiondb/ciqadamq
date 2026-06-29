#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/topic.rs"]
mod topic;

fuzz_target!(|data: (String, String)| {
    let (topic, filter) = data;
    let _ = topic::topic_matches(&topic, &filter);
    let _ = topic::has_wildcard(&filter);
});
