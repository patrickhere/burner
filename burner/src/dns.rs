//! dns messages a guest sent or got, read for the connection log. every byte
//! is hostile: the guest picks the question, and a server it controls can
//! pick the answers. bounded everywhere, never panics, and names come out in
//! presentation form with anything but letters, digits, - and _ escaped as
//! \DDD, so a name can't carry terminal escapes, newlines or lookalikes

use std::net::{Ipv4Addr, Ipv6Addr};

const HEADER: usize = 12;
const MAX_NAME: usize = 255;
const MAX_LABEL: usize = 63;
const MAX_LABELS: usize = 127;
const MAX_RECORDS: usize = 16;
const MAX_HOPS: usize = 16;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Query {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Answer {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub rcode: u8,
    /// A, AAAA and CNAME records, at most 16, in the order they came
    pub records: Vec<Data>,
    /// the message ended before everything it said it held
    pub truncated: bool,
}

/// what was wrong with it, in burner's own words
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Malformed(pub &'static str);

type R<T> = Result<T, Malformed>;

fn u16_at(b: &[u8], at: usize) -> R<u16> {
    match b.get(at..at + 2) {
        Some(x) => Ok(u16::from_be_bytes([x[0], x[1]])),
        None => Err(Malformed("cut off")),
    }
}

/// a label byte as it may be shown
fn push_escaped(out: &mut String, c: u8) {
    if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
        out.push(c as char);
    } else {
        out.push_str(&format!("\\{c:03}"));
    }
}

/// a name with no compression, as questions have: (name, bytes it took)
fn plain_name(b: &[u8], start: usize) -> R<(String, usize)> {
    let mut at = start;
    let mut out = String::new();
    let mut labels = 0;
    loop {
        let len = *b.get(at).ok_or(Malformed("cut off"))? as usize;
        if len == 0 {
            at += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return Err(Malformed("a compressed or odd label in the question"));
        }
        if len > MAX_LABEL {
            return Err(Malformed("a label over 63 bytes"));
        }
        labels += 1;
        if labels > MAX_LABELS {
            return Err(Malformed("too many labels"));
        }
        let label = b.get(at + 1..at + 1 + len).ok_or(Malformed("cut off"))?;
        if !out.is_empty() {
            out.push('.');
        }
        for &c in label {
            push_escaped(&mut out, c);
        }
        at += 1 + len;
        // the zero byte that ends it counts too
        if at - start >= MAX_NAME {
            return Err(Malformed("a name over 255 bytes"));
        }
    }
    if out.is_empty() {
        out.push('.');
    }
    Ok((out, at - start))
}

/// a name that may use compression pointers, which must point strictly
/// backwards and at most 16 times: (name, bytes it took where it started)
fn name(b: &[u8], start: usize) -> R<(String, usize)> {
    let mut at = start;
    let mut used = None;
    let mut hops = 0;
    let mut out = String::new();
    let mut wire = 0;
    let mut labels = 0;
    loop {
        let len = *b.get(at).ok_or(Malformed("cut off"))? as usize;
        match len & 0xc0 {
            0xc0 => {
                let ptr = (u16_at(b, at)? & 0x3fff) as usize;
                if ptr >= at {
                    return Err(Malformed("a compression pointer that doesn't point back"));
                }
                hops += 1;
                if hops > MAX_HOPS {
                    return Err(Malformed("too many compression pointers"));
                }
                // only the first pointer is where this name stops taking room
                if used.is_none() {
                    used = Some(at + 2 - start);
                }
                at = ptr;
                continue;
            }
            0 => {}
            _ => return Err(Malformed("an odd label type")),
        }
        if len == 0 {
            break;
        }
        if len > MAX_LABEL {
            return Err(Malformed("a label over 63 bytes"));
        }
        labels += 1;
        wire += 1 + len;
        if labels > MAX_LABELS || wire >= MAX_NAME {
            return Err(Malformed("a name over 255 bytes"));
        }
        let label = b.get(at + 1..at + 1 + len).ok_or(Malformed("cut off"))?;
        if !out.is_empty() {
            out.push('.');
        }
        for &c in label {
            push_escaped(&mut out, c);
        }
        at += 1 + len;
    }
    if out.is_empty() {
        out.push('.');
    }
    // with no pointer the name ended here, at its zero byte
    Ok((out, used.unwrap_or_else(|| at + 1 - start)))
}

/// the header and the one question both kinds of message start with
fn question(b: &[u8], response: bool) -> R<(u16, String, u16, usize)> {
    if b.len() < HEADER {
        return Err(Malformed("shorter than a dns header"));
    }
    let id = u16_at(b, 0)?;
    let flags = u16_at(b, 2)?;
    if (flags & 0x8000 != 0) != response {
        return Err(Malformed(if response {
            "not a response"
        } else {
            "not a query"
        }));
    }
    if u16_at(b, 4)? != 1 {
        return Err(Malformed("not exactly one question"));
    }
    let (qname, n) = plain_name(b, HEADER)?;
    let qtype = u16_at(b, HEADER + n)?;
    // the class: present, whatever it says
    u16_at(b, HEADER + n + 2)?;
    Ok((id, qname, qtype, HEADER + n + 4))
}

pub fn parse_query(b: &[u8]) -> R<Query> {
    let (id, name, qtype, _) = question(b, false)?;
    Ok(Query { id, name, qtype })
}

pub fn parse_response(b: &[u8]) -> R<Answer> {
    let (id, qname, qtype, mut at) = question(b, true)?;
    let rcode = (u16_at(b, 2)? & 0xf) as u8;
    let ancount = u16_at(b, 6)? as usize;
    let mut a = Answer {
        id,
        name: qname,
        qtype,
        rcode,
        records: Vec::new(),
        truncated: false,
    };
    for _ in 0..ancount.min(MAX_RECORDS) {
        // a cut-off answer (snaplen) is read as far as it goes
        let rec = (|| -> R<(Option<Data>, usize)> {
            let (_, n) = name(b, at)?;
            let rtype = u16_at(b, at + n)?;
            let rdlen = u16_at(b, at + n + 8)? as usize;
            let rd = at + n + 10;
            let data = b.get(rd..rd + rdlen).ok_or(Malformed("cut off"))?;
            let d = match (rtype, rdlen) {
                (1, 4) => Some(Data::A(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
                (28, 16) => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(data);
                    Some(Data::Aaaa(Ipv6Addr::from(o)))
                }
                (5, _) => Some(Data::Cname(name(b, rd)?.0)),
                _ => None,
            };
            Ok((d, rd + rdlen))
        })();
        match rec {
            Ok((d, next)) => {
                a.records.extend(d);
                at = next;
            }
            Err(Malformed("cut off")) => {
                a.truncated = true;
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(a)
}

pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        t => format!("TYPE{t}"),
    }
}

pub fn rcode_name(r: u8) -> String {
    match r {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        r => format!("RCODE{r}"),
    }
}

/// a name as parse_* write it: what the parent checks again before showing one
pub fn shown_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME * 4
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.\\".contains(&c))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn wire(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in name.split('.').filter(|l| !l.is_empty()) {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    pub(crate) fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        v.extend(wire(name));
        v.extend([(qtype >> 8) as u8, qtype as u8, 0, 1]);
        v
    }

    /// a response to query(): a CNAME pointing back at the question, then As
    pub(crate) fn response(id: u16, name: &str, ips: &[[u8; 4]]) -> Vec<u8> {
        let mut v = query(id, name, 1);
        v[2] = 0x81;
        v[3] = 0x80;
        let n = ips.len() as u16 + 1;
        v[6] = (n >> 8) as u8;
        v[7] = n as u8;
        // cname: name is a pointer to the question, rdata "cdn" + pointer
        v.extend([
            0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'c', b'd', b'n', 0xc0, 12,
        ]);
        let cname_at = v.len() - 6;
        for ip in ips {
            v.extend([0xc0, cname_at as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            v.extend(ip);
        }
        v
    }

    #[test]
    fn queries() {
        let q = parse_query(&query(0x1234, "pypi.org", 1)).unwrap();
        assert_eq!(
            q,
            Query {
                id: 0x1234,
                name: "pypi.org".into(),
                qtype: 1
            }
        );
        assert_eq!(parse_query(&query(1, ".", 2)).unwrap().name, ".");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(999), "TYPE999");
    }

    #[test]
    fn answers() {
        let r = parse_response(&response(
            7,
            "files.pythonhosted.org",
            &[[151, 101, 1, 63], [151, 101, 65, 63]],
        ))
        .unwrap();
        assert_eq!(r.name, "files.pythonhosted.org");
        assert_eq!(rcode_name(r.rcode), "NOERROR");
        assert_eq!(
            r.records,
            vec![
                Data::Cname("cdn.files.pythonhosted.org".into()),
                Data::A(Ipv4Addr::new(151, 101, 1, 63)),
                Data::A(Ipv4Addr::new(151, 101, 65, 63)),
            ]
        );
        assert!(!r.truncated);
        // a query is not an answer, and the other way round
        assert!(parse_response(&query(1, "a.b", 1)).is_err());
        assert!(parse_query(&response(1, "a.b", &[])).is_err());
    }

    #[test]
    fn cut_off_anywhere() {
        let full = response(9, "example.com", &[[1, 2, 3, 4], [5, 6, 7, 8]]);
        for n in 0..full.len() {
            // never a panic; past the question it's a truncated answer
            if let Ok(r) = parse_response(&full[..n]) {
                assert!(r.truncated, "{n}");
                assert!(r.records.len() <= 2);
            }
            let _ = parse_query(&full[..n]);
        }
    }

    #[test]
    fn pointers() {
        let mut r = response(1, "a.b", &[[1, 1, 1, 1]]);
        // the cname's pointer now points at itself
        let at = r.len() - 16 - 2;
        r[at] = 0xc0;
        r[at + 1] = at as u8;
        assert_eq!(
            parse_response(&r),
            Err(Malformed("a compression pointer that doesn't point back"))
        );
        // a pointer forward
        let mut r = response(1, "a.b", &[[1, 1, 1, 1]]);
        let at = r.len() - 16 - 2;
        r[at + 1] = 200;
        assert!(parse_response(&r).is_err());
        // a question may not be compressed at all
        let mut q = query(1, "a.b", 1);
        q[12] = 0xc0;
        q[13] = 0;
        assert!(parse_query(&q).is_err());
        // a chain of backward pointers longer than 16, hidden in the rdata
        // of a record of a type nobody reads
        let mut v = query(1, "x", 1);
        v[2] = 0x81;
        v[7] = 2;
        v.extend([0xc0, 12, 0, 99, 0, 1, 0, 0, 0, 1, 0, 42]);
        let base = v.len();
        v.extend([0xc0, 12]);
        for i in 0..20 {
            v.extend([0xc0, (base + 2 * i) as u8]);
        }
        let last = v.len() - 2;
        v.extend([
            0xc0, last as u8, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 0xc0, last as u8,
        ]);
        assert_eq!(
            parse_response(&v),
            Err(Malformed("too many compression pointers"))
        );
    }

    #[test]
    fn sizes() {
        let l63 = "a".repeat(63);
        assert!(parse_query(&query(1, &l63, 1)).is_ok());
        let mut q = query(1, "x", 1);
        q[12] = 64;
        assert!(parse_query(&q).is_err(), "64-byte label");
        let long = [l63.as_str(); 4].join(".");
        assert!(parse_query(&query(1, &long, 1)).is_err(), "256-byte name");
        let ok = format!("{}.{}", [l63.as_str(); 3].join("."), "a".repeat(61));
        assert!(parse_query(&query(1, &ok, 1)).is_ok(), "255-byte name");
        for qd in [0u8, 2] {
            let mut q = query(1, "a.b", 1);
            q[5] = qd;
            assert_eq!(parse_query(&q), Err(Malformed("not exactly one question")));
        }
        // more than 16 records: only 16 read
        let ips: Vec<[u8; 4]> = (0..40).map(|i| [10, 0, 0, i]).collect();
        let r = parse_response(&response(1, "a.b", &ips)).unwrap();
        assert_eq!(r.records.len(), MAX_RECORDS);
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let seed = response(3, "a.example", &[[1, 2, 3, 4]]);
        for _ in 0..20_000 {
            // flip a few bytes of a real answer, or make one up entirely
            let mut b = if next() % 2 == 0 {
                seed.clone()
            } else {
                (0..(next() % 80) as usize).map(|_| next() as u8).collect()
            };
            for _ in 0..(next() % 6) {
                if !b.is_empty() {
                    let i = next() as usize % b.len();
                    b[i] = next() as u8;
                }
            }
            if let Ok(a) = parse_response(&b) {
                assert!(a.records.len() <= MAX_RECORDS);
                assert!(shown_name_ok(&a.name));
            }
            if let Ok(q) = parse_query(&b) {
                assert!(shown_name_ok(&q.name));
            }
        }
    }

    #[test]
    fn every_byte_escaped() {
        for c in 0..=255u8 {
            let mut q = query(1, "ab", 1);
            q[14] = c;
            let name = parse_query(&q).unwrap().name;
            assert!(shown_name_ok(&name), "{c}: {name:?}");
            if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
                assert_eq!(name, format!("a{}", c as char));
            } else {
                assert_eq!(name, format!("a\\{c:03}"));
            }
        }
        assert!(!shown_name_ok("a\nb"));
        assert!(!shown_name_ok("\u{1b}[31m"));
        assert!(!shown_name_ok(""));
    }
}
