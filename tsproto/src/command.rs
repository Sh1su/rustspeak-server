//! Text command format: `name key=value key2=value2|key=value ...`

use std::fmt;

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            ' ' => out.push_str("\\s"),
            '|' => out.push_str("\\p"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c => out.push(c),
        }
    }
    out
}

pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('s') => out.push(' '),
            Some('p') => out.push('|'),
            Some('a') => out.push('\x07'),
            Some('b') => out.push('\x08'),
            Some('f') => out.push('\x0c'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('v') => out.push('\x0b'),
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

/// A parsed command. `items[0]` also carries the "static" arguments that
/// apply to every `|`-separated group.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Command {
    pub name: String,
    pub items: Vec<Vec<(String, String)>>,
}

impl Command {
    pub fn new(name: &str) -> Self {
        Command { name: name.into(), items: vec![Vec::new()] }
    }

    /// Builder: add an argument to the current (last) group.
    pub fn arg(mut self, k: &str, v: impl ToString) -> Self {
        self.push(k, v);
        self
    }

    pub fn push(&mut self, k: &str, v: impl ToString) {
        if self.items.is_empty() {
            self.items.push(Vec::new());
        }
        self.items.last_mut().unwrap().push((k.into(), v.to_string()));
    }

    /// Start a new `|` group.
    pub fn next_item(&mut self) {
        self.items.push(Vec::new());
    }

    pub fn add_item(&mut self, item: Vec<(String, String)>) {
        if self.items.len() == 1 && self.items[0].is_empty() {
            self.items[0] = item;
        } else {
            self.items.push(item);
        }
    }

    /// Parse a line. If `with_name` is false (ServerQuery responses), the
    /// first token is treated as an argument as well.
    pub fn parse(line: &str, with_name: bool) -> Command {
        let line = line.trim_end_matches(['\r', '\n']);
        let (name, rest) = if with_name {
            match line.split_once(' ') {
                Some((n, r)) => (n.to_string(), r),
                None => (line.to_string(), ""),
            }
        } else {
            (String::new(), line)
        };
        let mut items = Vec::new();
        for group in rest.split('|') {
            let mut item = Vec::new();
            for tok in group.split(' ').filter(|t| !t.is_empty()) {
                match tok.split_once('=') {
                    Some((k, v)) => item.push((k.to_string(), unescape(v))),
                    None => item.push((tok.to_string(), String::new())),
                }
            }
            items.push(item);
        }
        if items.is_empty() {
            items.push(Vec::new());
        }
        Command { name, items }
    }

    /// Value of `key` in group `i`, falling back to the static (first) group.
    pub fn get_in(&self, i: usize, key: &str) -> Option<&str> {
        fn find<'a>(it: &'a [(String, String)], key: &str) -> Option<&'a str> {
            it.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
        }
        self.items.get(i).and_then(|it| find(it, key)).or_else(|| self.items.first().and_then(|it| find(it, key)))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.get_in(0, key)
    }

    pub fn get_or<'a>(&'a self, key: &str, d: &'a str) -> &'a str {
        self.get(key).unwrap_or(d)
    }

    pub fn num<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn num_in<T: std::str::FromStr>(&self, i: usize, key: &str) -> Option<T> {
        self.get_in(i, key).and_then(|v| v.parse().ok())
    }

    pub fn has_flag(&self, flag: &str) -> bool {
        self.items.iter().flatten().any(|(k, _)| k == flag)
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                f.write_str("|")?;
            }
            for (j, (k, v)) in item.iter().enumerate() {
                if j > 0 || (i == 0 && !self.name.is_empty()) {
                    f.write_str(" ")?;
                }
                if v.is_empty() && k.starts_with('-') {
                    f.write_str(k)?;
                } else {
                    write!(f, "{}={}", k, escape(v))?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let c = Command::parse("notifytextmessage targetmode=2 msg=hello\\sworld\\p\\/x invokerid=1", true);
        assert_eq!(c.name, "notifytextmessage");
        assert_eq!(c.get("msg"), Some("hello world|/x"));
        assert_eq!(Command::parse(&c.to_string(), true), c);
    }

    #[test]
    fn groups() {
        let c = Command::parse("channellist cid=1 channel_name=a|cid=2 channel_name=b", true);
        assert_eq!(c.items.len(), 2);
        assert_eq!(c.get_in(1, "channel_name"), Some("b"));
    }
}
