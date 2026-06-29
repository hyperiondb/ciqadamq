pub fn topic_matches(topic: &str, filter: &str) -> bool {
    let mut t = topic.split('/');
    let mut f = filter.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => continue,
            (Some(fseg), Some(tseg)) if fseg == tseg => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

pub fn has_wildcard(filter: &str) -> bool {
    filter.bytes().any(|b| b == b'+' || b == b'#')
}
