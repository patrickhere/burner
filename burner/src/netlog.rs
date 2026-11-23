//! the connection log: every connection a VM tried, allowed or blocked, and
//! the dns it asked, recorded on the host. two producers feed it: on linux the
//! nflog reader (`__read-netlog`, a limited child), on macOS macnet. both
//! write small JSON lines; this side takes those as hostile (a producer the
//! guest took over could write anything), folds them into rows, and renders
//! the summary after a run and the table `burner log` prints. it never
//! decides anything about a packet: the filter already did

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::dns;
use crate::netmodel::{Model, Proto, Reason, Verdict};

/// a producer line longer than this is dropped and counted
pub const LINE_CAP: usize = 2048;
/// rows of each verdict past which new destinations are only counted
pub const ROW_CAP: usize = 10_000;
/// a stored log is cut to this
pub const FILE_CAP: usize = 1 << 20;
/// blocked lines in the summary after a run
const SUMMARY_LINES: usize = 5;
/// names kept per address, and addresses kept with names
const NAMES_PER_IP: usize = 3;
const NAMED_IPS: usize = 4096;
/// attempts kept waiting for their verdict. past this the oldest become
/// unknown, and the log isn't complete
const PENDING_CAP: usize = 20_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Conn,
    Dns,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// the far end replied: a syn-ack, an echo reply, a datagram back
    Answered,
    /// the far end reset it
    Refused,
    /// nothing came back while the VM ran
    NoAnswer,
    /// macOS: the host's connect timed out
    Timeout,
}

/// one row of the log: a destination and what happened to it, attempts with
/// the same verdict folded together. the schema is docs/json.md's. name,
/// names and answers come from dns a guest chose: shown escaped, and still
/// the guest's words
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// seconds since the run's network came up, first and last time seen
    pub t: f64,
    pub last: f64,
    pub count: u64,
    /// out only; in is kept for inbound ports later
    pub dir: String,
    pub kind: Kind,
    pub proto: Proto,
    pub dst: Ipv4Addr,
    /// null for icmp and protocols without ports
    pub port: Option<u16>,
    pub verdict: Verdict,
    pub reason: Option<Reason>,
    /// which range, interface or rule, in burner's words
    pub detail: Option<String>,
    /// allowed connections only
    pub outcome: Option<Outcome>,
    /// names that resolved to dst earlier in this run, at most 3
    pub names: Vec<String>,
    /// macOS fills these, linux leaves them null
    pub bytes_up: Option<u64>,
    pub bytes_down: Option<u64>,
    /// dns: the name and type asked
    pub name: Option<String>,
    pub qtype: Option<String>,
    pub rcode: Option<String>,
    pub answers: Vec<String>,
    /// dns: the message didn't parse, so there's no name
    pub malformed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    /// allowed connection attempts
    pub allowed: u64,
    /// blocked destinations, and attempts in all
    pub blocked: u64,
    pub blocked_attempts: u64,
    /// dns questions asked
    pub dns: u64,
    /// attempts whose verdict the log lost (a message that never came)
    #[serde(default)]
    pub unknown: u64,
}

/// one run's log: what burner log prints and the run's result.network
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetLog {
    pub id: String,
    pub net: String,
    pub platform: String,
    /// who ran it (the sudo caller on linux)
    pub owner: Option<u32>,
    pub started_unix: u64,
    pub secs: f64,
    /// false when something may be missing: lost messages, counters that
    /// couldn't be read, a producer that couldn't write
    pub complete: bool,
    /// gaps known of
    pub lost: u64,
    /// blocked attempts past the itemization limit, counted but not listed
    pub not_itemized: u64,
    /// producer lines that weren't valid, dropped
    pub invalid: u64,
    pub summary: Summary,
    pub events: Vec<Event>,
}

/// a dns message as a producer reports it
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsInfo {
    pub id: u16,
    pub name: Option<String>,
    pub qtype: Option<u16>,
    pub rcode: Option<u8>,
    #[serde(default)]
    pub answers: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub malformed: bool,
}

impl DnsInfo {
    pub fn query(b: &[u8], id_fallback: u16) -> DnsInfo {
        match dns::parse_query(b) {
            Ok(q) => DnsInfo {
                id: q.id,
                name: Some(q.name),
                qtype: Some(q.qtype),
                ..DnsInfo::default()
            },
            Err(_) => DnsInfo {
                id: id_fallback,
                malformed: true,
                ..DnsInfo::default()
            },
        }
    }

    pub fn response(b: &[u8]) -> DnsInfo {
        match dns::parse_response(b) {
            Ok(a) => DnsInfo {
                id: a.id,
                name: Some(a.name),
                qtype: Some(a.qtype),
                rcode: Some(a.rcode),
                answers: a
                    .records
                    .iter()
                    .map(|r| match r {
                        dns::Data::A(ip) => ip.to_string(),
                        dns::Data::Aaaa(ip) => ip.to_string(),
                        dns::Data::Cname(n) => n.clone(),
                    })
                    .collect(),
                truncated: a.truncated,
                malformed: false,
            },
            Err(_) => DnsInfo {
                id: b.get(..2).map_or(0, |x| u16::from_be_bytes([x[0], x[1]])),
                malformed: true,
                ..DnsInfo::default()
            },
        }
    }
}

/// what a producer writes, one JSON object a line
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case", deny_unknown_fields)]
pub enum Line {
    /// linux: one nflog message. p is the rule's prefix: t a new attempt
    /// (before the verdict), o let out, q a dns query let out, a the first
    /// reply of a flow, r a dns answer
    Pkt {
        p: String,
        /// netfilter hook: 1 input (to the host itself), 2 forward
        hook: u8,
        proto: u8,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        /// tcp flags, or the icmp type
        flags: u8,
        dns: Option<DnsInfo>,
        /// nflog's own sequence number, for counting gaps
        seq: Option<u32>,
    },
    /// macOS: macnet decided a new connection
    Conn {
        proto: Proto,
        sport: u16,
        dst: Ipv4Addr,
        port: u16,
        verdict: Verdict,
        reason: Option<Reason>,
    },
    /// macOS: how an allowed connection's connect went
    Outcome {
        sport: u16,
        dst: Ipv4Addr,
        port: u16,
        outcome: Outcome,
    },
    /// macOS: bytes a connection carried, when it closed
    Bytes {
        sport: u16,
        dst: Ipv4Addr,
        port: u16,
        up: u64,
        down: u64,
    },
    /// macOS: a dns query, allowed or refused
    Dns {
        dst: Ipv4Addr,
        sport: u16,
        verdict: Verdict,
        reason: Option<Reason>,
        dns: DnsInfo,
    },
    /// macOS: a resolver's answer
    Answer {
        dst: Ipv4Addr,
        sport: u16,
        dns: DnsInfo,
    },
    /// the producer couldn't write n lines, or saw n gaps
    Lost { n: u64 },
    /// macOS, when macnet exits: blocked attempts it decided, and those past
    /// its itemization limit
    Counts { blocked: u64, not_itemized: u64 },
}

/// a producer line, if it's one: short enough, the strict schema, and every
/// name in the form the dns parser writes
pub fn accept_line(s: &str) -> Option<Line> {
    if s.len() > LINE_CAP {
        return None;
    }
    let l: Line = serde_json::from_str(s).ok()?;
    let dns_ok = |d: &DnsInfo| {
        d.name.as_deref().is_none_or(dns::shown_name_ok)
            && d.answers.len() <= 16
            && d.answers
                .iter()
                .all(|a| a.parse::<std::net::IpAddr>().is_ok() || dns::shown_name_ok(a))
    };
    let ok = match &l {
        Line::Pkt { p, dns, .. } => {
            matches!(p.as_str(), "t" | "o" | "q" | "a" | "r") && dns.as_ref().is_none_or(dns_ok)
        }
        Line::Dns { dns, .. } | Line::Answer { dns, .. } => dns_ok(dns),
        _ => true,
    };
    ok.then_some(l)
}

/// a flow: protocol, the guest's port, destination, its port
type Flow = (Proto, u16, Ipv4Addr, u16);

#[derive(Hash, PartialEq, Eq, Clone)]
struct RowKey {
    kind: Kind,
    verdict: Verdict,
    proto: Proto,
    dst: Ipv4Addr,
    port: Option<u16>,
    name: Option<String>,
    qtype: Option<String>,
}

struct Try {
    at: Instant,
    flow: Flow,
    hook: u8,
    dns: Option<DnsInfo>,
}

/// linux: the slot's counters, read at teardown. every message the log
/// chains sent: new attempts (`tries`, of which `over` past the limit
/// weren't sent), what went out (`up`) and replies (`down`)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NetCounts {
    pub tries: u64,
    pub over: u64,
    pub up: u64,
    pub down: u64,
}

/// what says the log is whole, per platform
pub enum Check {
    /// linux: the counters, None when they couldn't be read
    Linux(Option<NetCounts>),
    /// macOS: whether macnet sent its final counts
    Mac(bool),
}

/// folds producer lines into rows. one per run
pub struct Collector {
    start: Instant,
    guest: Ipv4Addr,
    model: Model,
    rows: Vec<Event>,
    index: HashMap<RowKey, usize>,
    allowed_rows: usize,
    blocked_rows: usize,
    pending: VecDeque<Try>,
    /// an allowed flow's row, and whether it was answered
    flows: HashMap<Flow, (usize, Option<Outcome>)>,
    /// (resolver, guest port, query id) -> the dns row
    queries: HashMap<(Ipv4Addr, u16, u16), usize>,
    names: HashMap<Ipv4Addr, Vec<String>>,
    pub lost: u64,
    pub invalid: u64,
    /// blocked attempts not listed: past the rows cap here, or the
    /// producer's own limit
    pub not_itemized: u64,
    /// allowed connections past the rows cap: the log isn't complete then
    pub allowed_not_itemized: u64,
    /// linux: new attempts the reader sent, to check against the try chain's counter
    pub tries_seen: u64,
    /// linux: let-out (o, q) and reply (a, r) messages, against their counters
    pub up_seen: u64,
    pub down_seen: u64,
    /// attempts dropped from the waiting list for room
    pub evicted: u64,
    /// linux: connections let out with no attempt line before them, which
    /// the try chain's limit cut (they're itemized all the same)
    pub allowed_without_try: u64,
    /// macOS: macnet said its final counts
    pub saw_counts: bool,
    seq: Option<u32>,
    summary: Summary,
}

fn secs(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0).round() / 1000.0
}

impl Collector {
    pub fn new(model: Model, guest: Ipv4Addr, start: Instant) -> Collector {
        Collector {
            start,
            guest,
            model,
            rows: Vec::new(),
            index: HashMap::new(),
            allowed_rows: 0,
            blocked_rows: 0,
            pending: VecDeque::new(),
            flows: HashMap::new(),
            queries: HashMap::new(),
            names: HashMap::new(),
            lost: 0,
            invalid: 0,
            not_itemized: 0,
            allowed_not_itemized: 0,
            tries_seen: 0,
            up_seen: 0,
            down_seen: 0,
            evicted: 0,
            allowed_without_try: 0,
            saw_counts: false,
            seq: None,
            summary: Summary::default(),
        }
    }

    /// a raw line from a producer
    pub fn take(&mut self, raw: &str, now: Instant) {
        match accept_line(raw) {
            Some(l) => self.line(l, now),
            None => self.invalid += 1,
        }
    }

    pub fn line(&mut self, l: Line, now: Instant) {
        match l {
            Line::Pkt {
                p,
                hook,
                proto,
                src,
                dst,
                sport,
                dport,
                flags,
                dns,
                seq,
            } => {
                if let Some(s) = seq {
                    // nflog numbers each message it sends: a jump is messages lost
                    if let Some(prev) = self.seq
                        && s > prev.wrapping_add(1)
                        && s > prev
                    {
                        self.lost += u64::from(s - prev - 1);
                    }
                    self.seq = Some(s);
                }
                self.pkt(
                    &p,
                    hook,
                    Proto::from_ip(proto),
                    src,
                    dst,
                    sport,
                    dport,
                    flags,
                    dns,
                    now,
                );
            }
            Line::Conn {
                proto,
                sport,
                dst,
                port,
                verdict,
                reason,
            } => {
                let detail = self.detail_for(dst, proto, port, reason);
                let i = self.row(
                    Kind::Conn,
                    verdict,
                    proto,
                    dst,
                    has_ports(proto).then_some(port),
                    None,
                    None,
                    reason,
                    detail,
                    now,
                );
                if verdict == Verdict::Allowed
                    && let Some(i) = i
                {
                    self.flows.insert((proto, sport, dst, port), (i, None));
                }
            }
            Line::Outcome {
                sport,
                dst,
                port,
                outcome,
            } => self.outcome((Proto::Tcp, sport, dst, port), outcome),
            Line::Bytes {
                sport,
                dst,
                port,
                up,
                down,
            } => {
                if let Some(&(i, _)) = self.flows.get(&(Proto::Tcp, sport, dst, port)) {
                    let e = &mut self.rows[i];
                    e.bytes_up = Some(e.bytes_up.unwrap_or(0).saturating_add(up));
                    e.bytes_down = Some(e.bytes_down.unwrap_or(0).saturating_add(down));
                }
            }
            Line::Dns {
                dst,
                sport,
                verdict,
                reason,
                dns,
            } => {
                let detail = self.detail_for(dst, Proto::Udp, 53, reason);
                self.dns_row(dst, sport, verdict, reason, detail, dns, now);
            }
            Line::Answer { dst, sport, dns } => self.answer(dst, sport, dns),
            Line::Lost { n } => self.lost = self.lost.saturating_add(n),
            Line::Counts { not_itemized, .. } => {
                self.saw_counts = true;
                self.unlisted(not_itemized)
            }
        }
    }

    /// blocked attempts a producer counted without sending them (its own
    /// limit, or the try chain's on linux)
    pub fn unlisted(&mut self, n: u64) {
        self.not_itemized = self.not_itemized.saturating_add(n);
        self.summary.blocked_attempts = self.summary.blocked_attempts.saturating_add(n);
    }

    /// the words for a reason a producer gave: the model's range when the
    /// reason is a range, else the model's own words for it
    fn detail_for(
        &self,
        dst: Ipv4Addr,
        proto: Proto,
        port: u16,
        r: Option<Reason>,
    ) -> Option<String> {
        let r = r?;
        if let Some(b) = self.model.range_for(dst, r) {
            return Some(crate::netmodel::describe(b).1);
        }
        let e = self.model.expect(dst, proto, port);
        match r {
            Reason::Rate => Some("past the filter's rate limit".into()),
            Reason::Flows => Some("too many open connections".into()),
            _ if e.reason == Some(r) => e.detail,
            Reason::Route => Some("not routed through the default route".into()),
            Reason::Host => Some("this host".into()),
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn pkt(
        &mut self,
        p: &str,
        hook: u8,
        proto: Proto,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        flags: u8,
        dns: Option<DnsInfo>,
        now: Instant,
    ) {
        match p {
            // from the guest: anything else isn't this VM's
            "t" | "o" | "q" if src != self.guest => self.invalid += 1,
            "a" | "r" if dst != self.guest => self.invalid += 1,
            "t" => {
                self.tries_seen += 1;
                // its verdict waits for the end of the run: only then can
                // the counters say no "let out" message went missing
                self.pending.push_back(Try {
                    at: now,
                    flow: (proto, sport, dst, dport),
                    hook,
                    dns,
                });
                while self.pending.len() > PENDING_CAP {
                    let t = self.pending.pop_front().expect("not empty");
                    self.evicted += 1;
                    self.unknown(t);
                }
            }
            "o" | "q" => {
                self.up_seen += 1;
                let flow = (proto, sport, dst, dport);
                let pos = self.pending.iter().position(|t| t.flow == flow);
                let tried = pos.and_then(|i| self.pending.remove(i));
                let dns = dns.or_else(|| tried.and_then(|t| t.dns));
                if p == "q" || dns.is_some() {
                    let d = dns.unwrap_or(DnsInfo {
                        malformed: true,
                        ..DnsInfo::default()
                    });
                    self.dns_row(dst, sport, Verdict::Allowed, None, None, d, now);
                } else {
                    if pos.is_none() {
                        self.allowed_without_try += 1;
                    }
                    let port = has_ports(proto).then_some(dport);
                    let i = self.row(
                        Kind::Conn,
                        Verdict::Allowed,
                        proto,
                        dst,
                        port,
                        None,
                        None,
                        None,
                        None,
                        now,
                    );
                    if let Some(i) = i {
                        self.flows.entry(flow).or_insert((i, None));
                    }
                }
            }
            "a" => {
                self.down_seen += 1;
                let outcome = match proto {
                    // rst
                    Proto::Tcp if flags & 0x04 != 0 => Outcome::Refused,
                    _ => Outcome::Answered,
                };
                self.outcome((proto, dport, src, sport), outcome);
            }
            "r" => {
                self.down_seen += 1;
                if let Some(d) = dns {
                    self.answer(src, dport, d);
                }
            }
            _ => self.invalid += 1,
        }
    }

    fn outcome(&mut self, flow: Flow, o: Outcome) {
        let Some((i, seen)) = self.flows.get_mut(&flow) else {
            return;
        };
        if seen.is_none() {
            *seen = Some(o);
        }
        let e = &mut self.rows[*i];
        // a row of several attempts shows the best one
        e.outcome = Some(match e.outcome {
            Some(old) if old < o => old,
            _ => o,
        });
    }

    fn answer(&mut self, resolver: Ipv4Addr, gport: u16, d: DnsInfo) {
        let Some(&i) = self.queries.get(&(resolver, gport, d.id)) else {
            return;
        };
        let e = &mut self.rows[i];
        if e.rcode.is_none() {
            e.rcode = d.rcode.map(dns::rcode_name);
        }
        for a in &d.answers {
            if e.answers.len() < 16 && !e.answers.contains(a) {
                e.answers.push(a.clone());
            }
        }
        // only a name the same query asked labels the addresses
        let Some(name) = d.name.filter(|n| e.name.as_ref() == Some(n)) else {
            return;
        };
        for a in &d.answers {
            if let Ok(ip) = a.parse::<Ipv4Addr>() {
                if self.names.len() >= NAMED_IPS && !self.names.contains_key(&ip) {
                    continue;
                }
                let n = self.names.entry(ip).or_default();
                if n.len() < NAMES_PER_IP && !n.contains(&name) {
                    n.push(name.clone());
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dns_row(
        &mut self,
        dst: Ipv4Addr,
        sport: u16,
        verdict: Verdict,
        reason: Option<Reason>,
        detail: Option<String>,
        d: DnsInfo,
        now: Instant,
    ) {
        self.summary.dns += 1;
        let qtype = d.qtype.map(dns::qtype_name);
        let i = self.row(
            Kind::Dns,
            verdict,
            Proto::Udp,
            dst,
            Some(53),
            d.name.clone(),
            qtype,
            reason,
            detail,
            now,
        );
        if let Some(i) = i {
            if d.malformed {
                self.rows[i].malformed = true;
            }
            if verdict == Verdict::Allowed && self.queries.len() < 65536 {
                self.queries.insert((dst, sport, d.id), i);
            }
        }
    }

    /// add to a row, or start one. None when it was only counted
    #[allow(clippy::too_many_arguments)]
    fn row(
        &mut self,
        kind: Kind,
        verdict: Verdict,
        proto: Proto,
        dst: Ipv4Addr,
        port: Option<u16>,
        name: Option<String>,
        qtype: Option<String>,
        reason: Option<Reason>,
        detail: Option<String>,
        now: Instant,
    ) -> Option<usize> {
        let t = secs(now.saturating_duration_since(self.start));
        match (kind, verdict) {
            (Kind::Conn, Verdict::Allowed) => self.summary.allowed += 1,
            (_, Verdict::Blocked) => self.summary.blocked_attempts += 1,
            (_, Verdict::Unknown) => self.summary.unknown += 1,
            _ => {}
        }
        let key = RowKey {
            kind,
            verdict,
            proto,
            dst,
            port,
            name: name.clone(),
            qtype: qtype.clone(),
        };
        if let Some(&i) = self.index.get(&key) {
            let e = &mut self.rows[i];
            e.count += 1;
            e.last = t;
            // a name that resolved to it since the row began
            if kind == Kind::Conn
                && let Some(names) = self.names.get(&dst)
            {
                for n in names {
                    if e.names.len() < NAMES_PER_IP && !e.names.contains(n) {
                        e.names.push(n.clone());
                    }
                }
            }
            return Some(i);
        }
        let full = match verdict {
            Verdict::Allowed => self.allowed_rows >= ROW_CAP,
            Verdict::Blocked | Verdict::Unknown => self.blocked_rows >= ROW_CAP,
        };
        if full {
            match verdict {
                Verdict::Allowed | Verdict::Unknown => self.allowed_not_itemized += 1,
                Verdict::Blocked => self.not_itemized += 1,
            }
            return None;
        }
        match verdict {
            Verdict::Allowed => self.allowed_rows += 1,
            Verdict::Blocked => {
                self.blocked_rows += 1;
                self.summary.blocked += 1;
            }
            Verdict::Unknown => self.blocked_rows += 1,
        }
        let names = match kind {
            Kind::Conn => self.names.get(&dst).cloned().unwrap_or_default(),
            Kind::Dns => Vec::new(),
        };
        self.rows.push(Event {
            t,
            last: t,
            count: 1,
            dir: "out".into(),
            kind,
            proto,
            dst,
            port,
            verdict,
            reason,
            detail,
            outcome: None,
            names,
            bytes_up: None,
            bytes_down: None,
            name,
            qtype,
            rcode: None,
            answers: Vec::new(),
            malformed: false,
        });
        self.index.insert(key, self.rows.len() - 1);
        Some(self.rows.len() - 1)
    }

    /// an attempt with no "let out" after it, when that message may be the one
    /// that went missing: the log can't say what the filter did. the model's
    /// guess is in the words, never in the verdict
    fn unknown(&mut self, t: Try) {
        let (proto, sport, dst, dport) = t.flow;
        let port = has_ports(proto).then_some(dport);
        let e = self.model.expect(dst, proto, dport);
        let guess = match (e.verdict, e.detail) {
            (Verdict::Blocked, Some(d)) => format!("the model says blocked: {d}"),
            (Verdict::Allowed, _) => "the model says allowed".to_string(),
            _ => "the model says blocked".to_string(),
        };
        let detail = Some(format!(
            "the filter's verdict didn't reach the log, {guess}"
        ));
        match t.dns {
            Some(d) if proto == Proto::Udp && dport == 53 => {
                self.dns_row(dst, sport, Verdict::Unknown, None, detail, d, t.at)
            }
            _ => {
                self.row(
                    Kind::Conn,
                    Verdict::Unknown,
                    proto,
                    dst,
                    port,
                    None,
                    None,
                    None,
                    detail,
                    t.at,
                );
            }
        }
    }

    /// the kernel's verdict was no. the reason is the model's
    fn blocked(&mut self, t: Try) {
        let (proto, sport, dst, dport) = t.flow;
        let port = has_ports(proto).then_some(dport);
        let e = self.model.expect(dst, proto, dport);
        let (reason, detail) = match (e.reason, t.hook) {
            (Some(r), _) => (r, e.detail),
            // into the host itself (input), whatever the address says
            (None, 1) => (Reason::Host, Some("this host".into())),
            (None, _) => {
                let r = self.model.over_meter(proto, dport);
                let d = match r {
                    Reason::Rate => "past the filter's rate limit",
                    _ => "blocked by the filter, the model doesn't say why",
                };
                (r, Some(d.into()))
            }
        };
        let (reason, detail) = if t.hook == 1 && reason != Reason::Host {
            (Reason::Host, Some(format!("this host, {dst}")))
        } else {
            (reason, detail)
        };
        match t.dns {
            Some(d) if proto == Proto::Udp && dport == 53 => {
                self.dns_row(dst, sport, Verdict::Blocked, Some(reason), detail, d, t.at)
            }
            _ => {
                self.row(
                    Kind::Conn,
                    Verdict::Blocked,
                    proto,
                    dst,
                    port,
                    None,
                    None,
                    Some(reason),
                    detail,
                    t.at,
                );
            }
        }
    }

    /// messages the kernel sent that never arrived, by the counters. None
    /// when the counters can't be the ones these messages were counted in:
    /// fewer than arrived, as after a filter reload set them back to zero
    fn gap(&self, c: &NetCounts) -> Option<u64> {
        let sent = c
            .tries
            .checked_sub(c.over)?
            .checked_add(c.up)?
            .checked_add(c.down)?;
        let got = self.tries_seen + self.up_seen + self.down_seen;
        (self.tries_seen <= c.tries && self.up_seen <= c.up && self.down_seen <= c.down)
            .then(|| sent.checked_sub(got))
            .flatten()
    }

    /// the log as it stands once the VM is gone and every message is in
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        mut self,
        id: &str,
        net: &str,
        platform: &str,
        owner: Option<u32>,
        started_unix: u64,
        now: Instant,
        check: Check,
    ) -> NetLog {
        // an attempt with no "let out" message was blocked only if the
        // counters show every let-out message the kernel sent arrived: then
        // the one it would have had was never sent. to the host itself (the
        // input hook) it's blocked either way: burner's input chain drops
        // every packet from a tap, right after the log's jump
        let (counts_ok, established) = match check {
            Check::Mac(said) => (said, true),
            // the counters also catch a gap at the very end, which no
            // sequence number shows
            Check::Linux(Some(c)) => match self.gap(&c) {
                Some(gap) => {
                    self.lost = self.lost.max(gap);
                    self.unlisted(c.over - self.allowed_without_try.min(c.over));
                    (true, self.up_seen == c.up)
                }
                None => (false, false),
            },
            Check::Linux(None) => (false, false),
        };
        while let Some(t) = self.pending.pop_front() {
            if established || t.hook == 1 {
                self.blocked(t);
            } else {
                self.unknown(t);
            }
        }
        for (i, seen) in self.flows.values() {
            if seen.is_none() && self.rows[*i].outcome.is_none() {
                self.rows[*i].outcome = Some(Outcome::NoAnswer);
            }
        }
        let complete = counts_ok
            && self.lost == 0
            && self.allowed_not_itemized == 0
            && self.evicted == 0
            && self.summary.unknown == 0;
        let mut log = NetLog {
            id: id.into(),
            net: net.into(),
            platform: platform.into(),
            owner,
            started_unix,
            secs: secs(now.saturating_duration_since(self.start)),
            complete,
            lost: self.lost,
            not_itemized: self.not_itemized,
            invalid: self.invalid,
            summary: self.summary,
            events: self.rows,
        };
        cut_to(&mut log, FILE_CAP);
        log
    }
}

fn has_ports(p: Proto) -> bool {
    matches!(p, Proto::Tcp | Proto::Udp)
}

/// keep a log's JSON under cap: blocked rows go first (they're counted in
/// not_itemized), allowed ones only if that's not enough (then it's not complete)
pub fn cut_to(log: &mut NetLog, cap: usize) {
    let size = |l: &NetLog| serde_json::to_vec(l).map_or(usize::MAX, |v| v.len());
    if size(log) <= cap {
        return;
    }
    // rough size per row, so it's not a serialization per row dropped
    let per = (size(log) / log.events.len().max(1)).max(1);
    loop {
        let over = size(log).saturating_sub(cap);
        if over == 0 || log.events.is_empty() {
            break;
        }
        let n = over / per + 1;
        for _ in 0..n {
            let i = log
                .events
                .iter()
                .rposition(|e| e.verdict != Verdict::Allowed)
                .or_else(|| {
                    log.complete = false;
                    log.events.len().checked_sub(1)
                });
            let Some(i) = i else { break };
            let e = log.events.remove(i);
            if e.verdict == Verdict::Blocked {
                log.not_itemized = log.not_itemized.saturating_add(e.count);
            }
        }
    }
}

// ---- the old store ----

/// what 0.3.0 left in the state dir goes: nothing reads it any more
pub fn clear_old(state: &std::path::Path) {
    let dir = state.join("logs");
    let names = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok());
    for name in names {
        let id = name
            .strip_suffix(".json")
            .or_else(|| name.strip_suffix(".json.new"));
        if id.is_some_and(crate::ledger::valid_id) {
            let _ = std::fs::remove_file(dir.join(&name));
        }
    }
    let _ = std::fs::remove_dir(&dir);
}

// ---- a log from somewhere else ----

/// the keys a value of this type has when serialized
fn keys_of<T: Serialize>(sample: &T) -> Vec<String> {
    match serde_json::to_value(sample) {
        Ok(serde_json::Value::Object(m)) => m.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

fn only_keys(v: &serde_json::Value, keys: &[String]) -> Option<serde_json::Value> {
    let m = v.as_object()?;
    Some(serde_json::Value::Object(
        m.iter()
            .filter(|(k, _)| keys.contains(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    ))
}

impl NetLog {
    /// a log another burner wrote (the far end of -H, maybe a newer one): the
    /// fields this burner knows, read with the same types. a row it can't
    /// read (a kind it doesn't know yet) is left out, and then the log
    /// isn't complete. None when what's there isn't a log at all
    pub fn lenient(v: &serde_json::Value) -> Option<NetLog> {
        let event = Event {
            t: 0.0,
            last: 0.0,
            count: 0,
            dir: String::new(),
            kind: Kind::Conn,
            proto: Proto::Tcp,
            dst: Ipv4Addr::UNSPECIFIED,
            port: None,
            verdict: Verdict::Allowed,
            reason: None,
            detail: None,
            outcome: None,
            names: Vec::new(),
            bytes_up: None,
            bytes_down: None,
            name: None,
            qtype: None,
            rcode: None,
            answers: Vec::new(),
            malformed: false,
        };
        let sample = NetLog {
            id: String::new(),
            net: String::new(),
            platform: String::new(),
            owner: None,
            started_unix: 0,
            secs: 0.0,
            complete: false,
            lost: 0,
            not_itemized: 0,
            invalid: 0,
            summary: Summary::default(),
            events: Vec::new(),
        };
        let (top, sum, ev) = (
            keys_of(&sample),
            keys_of(&Summary::default()),
            keys_of(&event),
        );
        let mut o = only_keys(v, &top)?;
        if let Some(s) = o.get("summary").and_then(|s| only_keys(s, &sum)) {
            o["summary"] = s;
        }
        // a log has its rows, even when there are none
        let rows = o.get("events")?.as_array()?.clone();
        o["events"] = serde_json::Value::Array(Vec::new());
        let mut log: NetLog = serde_json::from_value(o).ok()?;
        let mut left_out = false;
        for r in &rows {
            let Some(mut r) = only_keys(r, &ev) else {
                left_out = true;
                continue;
            };
            // a reason this burner doesn't know yet: the row without it
            let e = serde_json::from_value::<Event>(r.clone()).ok().or_else(|| {
                r["reason"] = serde_json::Value::Null;
                serde_json::from_value::<Event>(r).ok()
            });
            match e {
                Some(e) => log.events.push(e),
                None => left_out = true,
            }
        }
        if left_out {
            log.complete = false;
        }
        cut_to(&mut log, FILE_CAP);
        Some(log)
    }
}

// ---- words ----

fn dest(e: &Event) -> String {
    match (e.kind, e.port) {
        (Kind::Dns, _) => format!(
            "dns {} {} {}",
            e.dst,
            e.name
                .as_deref()
                .unwrap_or(if e.malformed { "(malformed)" } else { "?" }),
            e.qtype.as_deref().unwrap_or("")
        )
        .trim_end()
        .to_string(),
        (_, Some(p)) => format!("{} {}:{p}", e.proto.name(), e.dst),
        (_, None) => format!("{} {}", e.proto.name(), e.dst),
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// the lines after a run, each starting "burner: "
pub fn summary_lines(log: &NetLog) -> Vec<String> {
    let s = &log.summary;
    let blocked = if s.blocked_attempts > s.blocked {
        format!("{} blocked ({} attempts)", s.blocked, s.blocked_attempts)
    } else {
        format!("{} blocked", s.blocked)
    };
    let mut head = format!(
        "net {}: {} out, {blocked}, {}",
        log.net,
        plural(s.allowed, "connection", "connections"),
        plural(s.dns, "dns lookup", "dns lookups"),
    );
    if s.unknown > 0 {
        head += &format!(", {} unknown", s.unknown);
    }
    if !log.complete {
        head += ", log incomplete";
        if log.lost > 0 {
            head += &format!(" ({} lost)", log.lost);
        }
    }
    head += &format!(" (burner log {} for all of it)", log.id);
    let mut out = vec![head];
    if let Some(r) = reached(log) {
        out.push(format!("  reached: {r}"));
    }
    let mut blocked: Vec<&Event> = log
        .events
        .iter()
        .filter(|e| e.verdict == Verdict::Blocked)
        .collect();
    blocked.sort_by(|a, b| a.t.total_cmp(&b.t));
    let w = blocked
        .iter()
        .take(SUMMARY_LINES)
        .map(|e| dest(e).len())
        .max()
        .unwrap_or(0);
    for e in blocked.iter().take(SUMMARY_LINES) {
        let times = if e.count > 1 {
            format!("   x{}", e.count)
        } else {
            String::new()
        };
        out.push(format!(
            "  blocked  {:<w$}  {}{times}",
            dest(e),
            e.detail
                .as_deref()
                .unwrap_or(e.reason.map_or("", |r| r.name()))
        ));
    }
    let more = blocked.len().saturating_sub(SUMMARY_LINES) as u64 + log.not_itemized;
    if more > 0 {
        out.push(format!("  and {more} more blocked, not listed here"));
    }
    if s.unknown > 0 {
        out.push(format!(
            "  {} attempts with no verdict: the log lost what the filter did with them",
            s.unknown
        ));
    }
    out.into_iter().map(|l| sanitize(&l)).collect()
}

/// names shown on the reached line, and how long it gets
const REACHED_NAMES: usize = 3;
const REACHED_WIDTH: usize = 60;

/// where the run went: the allowed connections' names (the address when
/// there's none), in the order they were first seen. None when nothing
/// was allowed out
fn reached(log: &NetLog) -> Option<String> {
    let mut rows: Vec<&Event> = log
        .events
        .iter()
        .filter(|e| e.verdict == Verdict::Allowed && e.kind == Kind::Conn)
        .collect();
    rows.sort_by(|a, b| a.t.total_cmp(&b.t));
    let mut names: Vec<String> = Vec::new();
    for e in rows {
        let n = e
            .names
            .first()
            .cloned()
            .unwrap_or_else(|| e.dst.to_string());
        if !names.contains(&n) {
            names.push(n);
        }
    }
    let cut = |n: &str| -> String {
        if n.chars().count() > REACHED_WIDTH {
            n.chars().take(REACHED_WIDTH - 3).collect::<String>() + "..."
        } else {
            n.to_string()
        }
    };
    let mut shown: Vec<String> = Vec::new();
    let mut width = 0;
    for n in &names {
        let n = cut(n);
        if !shown.is_empty()
            && (shown.len() == REACHED_NAMES || width + 2 + n.len() > REACHED_WIDTH)
        {
            break;
        }
        width += n.len() + 2;
        shown.push(n);
    }
    if shown.is_empty() {
        return None;
    }
    let more = names.len() - shown.len();
    let mut s = shown.join(", ");
    if more > 0 {
        s += &format!(", +{more} more");
    }
    Some(s)
}

/// the full table, as burner log and --log full print it
pub fn table(log: &NetLog) -> String {
    let mut s = format!(
        "net {}, {:.1}s, log {}",
        log.net,
        log.secs,
        if log.complete {
            "complete"
        } else {
            "incomplete"
        }
    );
    if log.lost > 0 {
        s += &format!(", {} lost", log.lost);
    }
    // net is the far end's word in a -H copy
    let mut s = sanitize(&s);
    s.push('\n');
    let mut rows: Vec<[String; 6]> = vec![[
        "time".into(),
        "verdict".into(),
        "proto".into(),
        "destination".into(),
        "port".into(),
        "name".into(),
    ]];
    let mut notes = vec!["note".to_string()];
    for e in &log.events {
        let proto = match e.kind {
            Kind::Dns => "dns",
            Kind::Conn => e.proto.name(),
        };
        let name = match e.kind {
            Kind::Dns => format!(
                "{} {}",
                e.name
                    .as_deref()
                    .unwrap_or(if e.malformed { "(malformed)" } else { "-" }),
                e.qtype.as_deref().unwrap_or("")
            )
            .trim_end()
            .to_string(),
            Kind::Conn if e.names.is_empty() => "-".into(),
            Kind::Conn => e.names.join(","),
        };
        let mut note = match (e.verdict, e.kind) {
            (Verdict::Blocked | Verdict::Unknown, _) => e
                .detail
                .clone()
                .unwrap_or_else(|| e.reason.map_or("", |r| r.name()).into()),
            (Verdict::Allowed, Kind::Dns) if !e.answers.is_empty() => {
                format!("-> {}", e.answers.join(", "))
            }
            (Verdict::Allowed, Kind::Dns) => e.rcode.clone().unwrap_or_else(|| "no answer".into()),
            (Verdict::Allowed, Kind::Conn) => match e.outcome {
                Some(Outcome::Answered) => "answered".into(),
                Some(Outcome::Refused) => "refused".into(),
                Some(Outcome::Timeout) => "timed out".into(),
                Some(Outcome::NoAnswer) | None => "no answer".into(),
            },
        };
        if let (Some(u), Some(d)) = (e.bytes_up, e.bytes_down) {
            note += &format!(", {u} up {d} down");
        }
        if e.count > 1 {
            note += &format!("  x{}", e.count);
        }
        rows.push([
            format!("{:.2}s", e.t),
            match e.verdict {
                Verdict::Allowed => "allowed".into(),
                Verdict::Blocked => "blocked".into(),
                Verdict::Unknown => "unknown".into(),
            },
            proto.into(),
            e.dst.to_string(),
            e.port.map_or_else(|| "-".into(), |p| p.to_string()),
            name,
        ]);
        notes.push(note);
    }
    let mut w = [0usize; 6];
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.len()).min(40);
        }
    }
    for (r, note) in rows.iter().zip(&notes) {
        let mut line = String::new();
        for (i, c) in r.iter().enumerate() {
            line += &format!("  {:<width$}", c, width = w[i]);
        }
        line += &format!("  {note}");
        s += &sanitize(line.trim_end());
        s.push('\n');
    }
    if log.not_itemized > 0 {
        s += &format!(
            "  and {} more blocked attempts, counted but not listed\n",
            log.not_itemized
        );
    }
    if log.events.is_empty() {
        s += "  nothing: the VM didn't try to reach anything\n";
    }
    s
}

/// what's printed passes the terminal filter even though names were
/// escaped when they were parsed
fn sanitize(s: &str) -> String {
    String::from_utf8_lossy(&crate::output::escape_controls(s.as_bytes())).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::net::{self, Mode, parse_addrs, parse_routes};
    use crate::netmodel::Platform;

    const GUEST: Ipv4Addr = Ipv4Addr::new(172, 29, 217, 2);

    fn model(mode: Mode) -> Model {
        let cfg = Config::default();
        let b = net::sources_from(
            &cfg,
            None,
            &parse_addrs(net::tests::HOMELAB_ADDRS.as_bytes()).unwrap(),
            &parse_routes(net::tests::HOMELAB_ROUTES.as_bytes(), "eth0").unwrap(),
        )
        .unwrap();
        Model::new(&cfg, mode, Platform::Linux, b)
    }

    fn pkt(p: &str, proto: u8, src: &str, dst: &str, sport: u16, dport: u16, flags: u8) -> Line {
        Line::Pkt {
            p: p.into(),
            hook: 2,
            proto,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            sport,
            dport,
            flags,
            dns: None,
            seq: None,
        }
    }

    fn with_dns(mut l: Line, d: DnsInfo) -> Line {
        if let Line::Pkt { dns, .. } = &mut l {
            *dns = Some(d);
        }
        l
    }

    /// counters that say every message the kernel sent came through
    fn whole(c: &Collector) -> NetCounts {
        NetCounts {
            tries: c.tries_seen,
            over: 0,
            up: c.up_seen,
            down: c.down_seen,
        }
    }

    fn finish_with(c: Collector, t0: Instant, check: Check) -> NetLog {
        c.finish(
            "burner-3fa1c2",
            "web",
            "linux",
            Some(1000),
            0,
            t0 + Duration::from_secs(14),
            check,
        )
    }

    fn finish(c: Collector, t0: Instant) -> NetLog {
        let w = whole(&c);
        finish_with(c, t0, Check::Linux(Some(w)))
    }

    /// a run like the one in the design doc: two dns lookups, two https
    /// connections, three tries at the lan's ssh, cloud metadata, a dns
    /// query to a resolver that isn't one
    fn sample() -> NetLog {
        let t0 = Instant::now();
        let mut c = Collector::new(model(Mode::Web), GUEST, t0);
        let g = "172.29.217.2";
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let q = dns::tests::query(0x11, "pypi.org", 1);
        let r = dns::tests::response(0x11, "pypi.org", &[[151, 101, 0, 223], [151, 101, 64, 223]]);
        c.line(
            with_dns(
                pkt("t", 17, g, "9.9.9.9", 4000, 53, 0),
                DnsInfo::query(&q, 0),
            ),
            at(410),
        );
        c.line(
            with_dns(
                pkt("q", 17, g, "9.9.9.9", 4000, 53, 0),
                DnsInfo::query(&q, 0),
            ),
            at(410),
        );
        c.line(
            with_dns(
                pkt("r", 17, "9.9.9.9", g, 53, 4000, 0),
                DnsInfo::response(&r),
            ),
            at(420),
        );
        c.line(pkt("t", 6, g, "151.101.0.223", 5000, 443, 0x02), at(460));
        c.line(pkt("o", 6, g, "151.101.0.223", 5000, 443, 0x02), at(460));
        c.line(pkt("a", 6, "151.101.0.223", g, 443, 5000, 0x12), at(470));
        for i in 0..3 {
            c.line(
                pkt("t", 6, g, "192.168.1.1", 6000 + i, 22, 0x02),
                at(1300 + 1000 * u64::from(i)),
            );
        }
        c.line(pkt("t", 6, g, "169.254.169.254", 7000, 80, 0x02), at(5020));
        let evil = dns::tests::query(0x22, "evil.example", 1);
        c.line(
            with_dns(
                pkt("t", 17, g, "8.8.8.8", 4001, 53, 0),
                DnsInfo::query(&evil, 0),
            ),
            at(6400),
        );
        // allowed, never answered
        c.line(pkt("t", 6, g, "140.82.112.3", 5001, 443, 0x02), at(7000));
        c.line(pkt("o", 6, g, "140.82.112.3", 5001, 443, 0x02), at(7000));
        // refused
        c.line(pkt("t", 6, g, "151.101.64.223", 5002, 80, 0x02), at(7100));
        c.line(pkt("o", 6, g, "151.101.64.223", 5002, 80, 0x02), at(7100));
        c.line(pkt("a", 6, "151.101.64.223", g, 80, 5002, 0x14), at(7110));
        finish(c, t0)
    }

    #[test]
    fn folds_and_decides() {
        let log = sample();
        let find = |dst: &str, port: u16| {
            log.events
                .iter()
                .find(|e| e.dst.to_string() == dst && e.port == Some(port))
                .unwrap_or_else(|| panic!("{dst}:{port} in {:#?}", log.events))
        };
        let lan = find("192.168.1.1", 22);
        assert_eq!(
            (lan.verdict, lan.reason, lan.count),
            (Verdict::Blocked, Some(Reason::Route), 3)
        );
        assert_eq!(
            lan.detail.as_deref(),
            Some("your lan (192.168.1.0/24 on eth0)")
        );
        assert_eq!((lan.t, lan.last), (1.3, 3.3));
        let md = find("169.254.169.254", 80);
        assert_eq!(md.reason, Some(Reason::Special));
        let https = find("151.101.0.223", 443);
        assert_eq!(
            (https.verdict, https.outcome),
            (Verdict::Allowed, Some(Outcome::Answered))
        );
        assert_eq!(https.names, vec!["pypi.org"]);
        assert_eq!(find("140.82.112.3", 443).outcome, Some(Outcome::NoAnswer));
        let refused = find("151.101.64.223", 80);
        assert_eq!(refused.outcome, Some(Outcome::Refused));
        assert_eq!(refused.names, vec!["pypi.org"]);
        let q = log
            .events
            .iter()
            .find(|e| e.name.as_deref() == Some("pypi.org"))
            .unwrap();
        assert_eq!((q.kind, q.verdict), (Kind::Dns, Verdict::Allowed));
        assert_eq!(
            q.answers,
            vec!["cdn.pypi.org", "151.101.0.223", "151.101.64.223"]
        );
        assert_eq!(q.rcode.as_deref(), Some("NOERROR"));
        let evil = log
            .events
            .iter()
            .find(|e| e.name.as_deref() == Some("evil.example"))
            .unwrap();
        assert_eq!(
            (evil.verdict, evil.reason),
            (Verdict::Blocked, Some(Reason::NotResolver))
        );
        assert_eq!(
            log.summary,
            Summary {
                allowed: 3,
                blocked: 3,
                blocked_attempts: 5,
                dns: 2,
                unknown: 0,
            }
        );
        assert!(log.complete);
    }

    #[test]
    fn summary_words() {
        let l = summary_lines(&sample());
        assert_eq!(
            l[0],
            "net web: 3 connections out, 3 blocked (5 attempts), 2 dns lookups (burner log burner-3fa1c2 for all of it)"
        );
        assert_eq!(l[1], "  reached: pypi.org, 140.82.112.3");
        assert_eq!(
            l[2],
            "  blocked  tcp 192.168.1.1:22          your lan (192.168.1.0/24 on eth0)   x3"
        );
        assert!(l[3].starts_with("  blocked  tcp 169.254.169.254:80      cloud metadata"));
        assert!(
            l[4].starts_with("  blocked  dns 8.8.8.8 evil.example A  not one of net.resolvers")
        );
        assert_eq!(l.len(), 5);
        let t = table(&sample());
        assert!(t.starts_with("net web, 14.0s, log complete\n"), "{t}");
        assert!(t.contains("pypi.org A"), "{t}");
        assert!(t.contains("-> cdn.pypi.org, 151.101.0.223"), "{t}");
        assert!(t.contains("answered"), "{t}");
        assert!(t.contains("refused"), "{t}");
    }

    #[test]
    fn caps_and_counts() {
        let t0 = Instant::now();
        let mut c = Collector::new(model(Mode::Web), GUEST, t0);
        let n = ROW_CAP as u32 + 50;
        for i in 0..n {
            let dst = Ipv4Addr::from(0x0a00_0000 + i);
            c.line(
                Line::Pkt {
                    p: "t".into(),
                    hook: 2,
                    proto: 6,
                    src: GUEST,
                    dst,
                    sport: 1,
                    dport: 22,
                    flags: 2,
                    dns: None,
                    seq: None,
                },
                t0,
            );
        }
        // an allowed one after the flood still gets its row
        c.line(pkt("t", 6, "172.29.217.2", "140.82.112.3", 9, 443, 2), t0);
        c.line(pkt("o", 6, "172.29.217.2", "140.82.112.3", 9, 443, 2), t0);
        let log = finish(c, t0);
        assert!(log.events.iter().any(|e| e.verdict == Verdict::Allowed));
        assert!(log.not_itemized >= 50, "{}", log.not_itemized);
        assert!(serde_json::to_vec(&log).unwrap().len() <= FILE_CAP);
        assert_eq!(log.summary.blocked_attempts, u64::from(n));
        assert!(
            log.complete,
            "blocked rows past the cap are counted, that's complete"
        );
        let l = summary_lines(&log);
        assert!(l.last().unwrap().contains("more blocked, not listed here"));
    }

    /// an attempt and no "let out" after it is blocked only when the counters
    /// show no let-out message went missing, a trailing one included
    #[test]
    fn a_lost_message_makes_unknown_not_blocked() {
        let g = "172.29.217.2";
        let run = |lost_up: u64, readable: bool| {
            let t0 = Instant::now();
            let mut c = Collector::new(model(Mode::Web), GUEST, t0);
            // allowed in fact, but its "o" never arrives: the last message lost
            c.line(pkt("t", 6, g, "140.82.112.3", 5000, 443, 2), t0);
            let mut host = pkt("t", 6, g, "172.29.217.1", 5001, 22, 2);
            if let Line::Pkt { hook, .. } = &mut host {
                *hook = 1;
            }
            c.line(host, t0);
            let mut w = whole(&c);
            w.up += lost_up;
            finish_with(c, t0, Check::Linux(readable.then_some(w)))
        };
        let row = |log: &NetLog, dst: &str| {
            log.events
                .iter()
                .find(|e| e.dst.to_string() == dst)
                .unwrap()
                .clone()
        };
        // every message came: the filter really dropped it
        let log = run(0, true);
        assert_eq!(row(&log, "140.82.112.3").verdict, Verdict::Blocked);
        assert!(log.complete);
        // one let-out message missing at the very end: no gap shows it, the
        // counter does
        for log in [run(1, true), run(0, false)] {
            let e = row(&log, "140.82.112.3");
            assert_eq!(e.verdict, Verdict::Unknown, "{log:#?}");
            assert!(e.detail.unwrap().contains("the model says allowed"));
            assert!(!log.complete);
            assert_eq!(log.summary.unknown, 1);
            assert_eq!(log.summary.blocked, 1, "the host one only");
            // into the host itself, burner's input chain drops it right after
            assert_eq!(row(&log, "172.29.217.1").verdict, Verdict::Blocked);
            let l = summary_lines(&log);
            assert!(l[0].contains("1 unknown, log incomplete"), "{l:?}");
            assert!(
                l.iter()
                    .any(|x| x.contains("the log lost what the filter did"))
            );
            assert!(table(&log).contains("unknown"));
        }
        assert_eq!(run(1, true).lost, 1);
    }

    #[test]
    fn hostile_lines() {
        let t0 = Instant::now();
        let mut c = Collector::new(model(Mode::Web), GUEST, t0);
        let long = format!(
            "{{\"k\":\"lost\",\"n\":1,\"x\":\"{}\"}}",
            "a".repeat(LINE_CAP)
        );
        for bad in [
            "not json",
            r#"{"k":"lost","n":1,"extra":2}"#,
            r#"{"k":"nope"}"#,
            r#"{"k":"pkt","p":"x","hook":2,"proto":6,"src":"172.29.217.2","dst":"1.1.1.1","sport":1,"dport":2,"flags":0,"dns":null,"seq":null}"#,
            r#"{"k":"dns","dst":"1.1.1.1","sport":1,"verdict":"allowed","reason":null,"dns":{"id":1,"name":"\u001b[31mred","qtype":1,"rcode":null}}"#,
            r#"{"k":"answer","dst":"1.1.1.1","sport":1,"dns":{"id":1,"name":"a","qtype":1,"rcode":0,"answers":["a\nb"]}}"#,
            long.as_str(),
        ] {
            c.take(bad, t0);
        }
        assert_eq!(c.invalid, 7);
        // another VM's packet, or a forged source, is dropped too
        c.line(pkt("o", 6, "172.29.217.6", "1.1.1.1", 1, 443, 2), t0);
        c.take(r#"{"k":"lost","n":2}"#, t0);
        let log = finish(c, t0);
        assert!(log.events.is_empty());
        assert_eq!((log.invalid, log.lost, log.complete), (8, 2, false));
        assert!(summary_lines(&log)[0].contains("log incomplete (2 lost)"));
    }

    #[test]
    fn counters_behind_the_log() {
        // the counters were set back mid-run: past the guard on each one,
        // fewer sent than arrived. that's counters that don't fit, not a panic
        let t0 = Instant::now();
        let mut c = Collector::new(model(Mode::Web), GUEST, t0);
        for p in [22, 23, 24, 25] {
            c.line(pkt("t", 6, "172.29.217.2", "10.0.0.1", 1, p, 2), t0);
        }
        let reset = NetCounts {
            tries: c.tries_seen,
            over: 3,
            up: 0,
            down: 0,
        };
        let log = finish_with(c, t0, Check::Linux(Some(reset)));
        assert!(!log.complete);
        assert_eq!(log.lost, 0);
    }

    #[test]
    fn sequence_gaps() {
        let t0 = Instant::now();
        let mut c = Collector::new(model(Mode::Web), GUEST, t0);
        for s in [1u32, 2, 3, 7, 8] {
            let mut l = pkt("t", 6, "172.29.217.2", "10.0.0.1", 1, 22, 2);
            if let Line::Pkt { seq, .. } = &mut l {
                *seq = Some(s);
            }
            c.line(l, t0);
        }
        let log = finish(c, t0);
        assert_eq!(log.lost, 3);
        assert!(!log.complete);
    }

    #[test]
    fn mac_lines() {
        let t0 = Instant::now();
        let mut m = model(Mode::Web);
        m.platform = Platform::Mac;
        let mut c = Collector::new(m, GUEST, t0);
        for l in [
            r#"{"k":"conn","proto":"tcp","sport":5,"dst":"140.82.112.3","port":443,"verdict":"allowed","reason":null}"#,
            r#"{"k":"outcome","sport":5,"dst":"140.82.112.3","port":443,"outcome":"answered"}"#,
            r#"{"k":"bytes","sport":5,"dst":"140.82.112.3","port":443,"up":517,"down":4096}"#,
            r#"{"k":"conn","proto":"tcp","sport":6,"dst":"192.168.1.1","port":80,"verdict":"blocked","reason":"host"}"#,
            r#"{"k":"conn","proto":"icmp","sport":0,"dst":"1.1.1.1","port":0,"verdict":"blocked","reason":"proto"}"#,
            r#"{"k":"counts","blocked":2,"not_itemized":0}"#,
        ] {
            c.take(l, t0);
        }
        assert_eq!(c.invalid, 0);
        let log = c.finish("burner-1", "web", "macos", None, 0, t0, Check::Mac(true));
        let gh = &log.events[0];
        assert_eq!(
            (gh.outcome, gh.bytes_up, gh.bytes_down),
            (Some(Outcome::Answered), Some(517), Some(4096))
        );
        assert_eq!(log.events[1].reason, Some(Reason::Host));
        assert_eq!(log.events[2].proto, Proto::Icmp);
    }

    #[test]
    fn lenient_reads_a_newer_log() {
        let log = sample();
        let mut v = serde_json::to_value(&log).unwrap();
        // what's this burner's own passes as it is
        assert_eq!(NetLog::lenient(&v).unwrap(), log);
        assert!(serde_json::from_value::<NetLog>(v.clone()).is_ok());
        // a newer far end: a field more at every level, a reason and a kind
        // this burner doesn't know
        v["report"] = "x".into();
        v["summary"]["http"] = 3.into();
        v["events"][0]["tls"] = true.into();
        let mut odd = v["events"][1].clone();
        odd["reason"] = "geo".into();
        let mut http = v["events"][1].clone();
        http["kind"] = "http".into();
        v["events"].as_array_mut().unwrap().push(odd);
        v["events"].as_array_mut().unwrap().push(http);
        assert!(
            serde_json::from_value::<NetLog>(v.clone()).is_err(),
            "strict refuses it"
        );
        let l = NetLog::lenient(&v).unwrap();
        assert_eq!(l.events.len(), log.events.len() + 1);
        assert_eq!(l.events.last().unwrap().reason, None);
        assert_eq!(l.summary, log.summary);
        assert!(!l.complete, "the http row was left out");
        // a header that would drive a terminal is shown escaped
        let mut esc = v.clone();
        esc["net"] = "web\u{1b}]0;x\u{7}".into();
        let t = table(&NetLog::lenient(&esc).unwrap());
        assert!(
            t.starts_with("net web\\x1b]0;x\\x07, ") && !t.contains('\u{1b}'),
            "{t}"
        );
        // not a log at all: no rows, or rows that aren't a list
        let mut no_rows = v.clone();
        no_rows.as_object_mut().unwrap().remove("events");
        assert!(NetLog::lenient(&no_rows).is_none());
        no_rows["events"] = "x".into();
        assert!(NetLog::lenient(&no_rows).is_none());
        assert!(NetLog::lenient(&serde_json::json!({"pad": "aaaa"})).is_none());
        assert!(NetLog::lenient(&serde_json::json!("x")).is_none());
    }

    #[test]
    fn reached_names() {
        let log = sample();
        assert_eq!(summary_lines(&log)[1], "  reached: pypi.org, 140.82.112.3");
        let mut big = log.clone();
        big.events
            .retain(|e| e.verdict != Verdict::Allowed || e.kind != Kind::Conn);
        assert!(reached(&big).is_none());
        let row = log
            .events
            .iter()
            .find(|e| e.kind == Kind::Conn && e.verdict == Verdict::Allowed)
            .unwrap();
        for i in 0..6u8 {
            let mut e = row.clone();
            e.t = f64::from(i);
            e.dst = Ipv4Addr::new(1, 1, 1, i);
            e.names = if i < 2 {
                vec![format!("n{i}.example")]
            } else {
                vec![]
            };
            big.events.push(e);
        }
        // the same name twice counts once
        let mut dup = row.clone();
        dup.t = 9.0;
        dup.names = vec!["n0.example".into()];
        big.events.push(dup);
        assert_eq!(
            reached(&big).unwrap(),
            "n0.example, n1.example, 1.1.1.2, +3 more"
        );
        let mut long = row.clone();
        long.t = -1.0;
        long.names = vec!["x".repeat(300)];
        big.events.push(long);
        let r = reached(&big).unwrap();
        assert_eq!(r, format!("{}..., +6 more", "x".repeat(57)));
    }

    #[test]
    fn schema_round_trip() {
        let log = sample();
        let s = serde_json::to_string(&log).unwrap();
        let back: NetLog = serde_json::from_str(&s).unwrap();
        assert_eq!(back, log);
        let e = serde_json::to_value(&log.events[0]).unwrap();
        for k in [
            "t",
            "last",
            "count",
            "dir",
            "kind",
            "proto",
            "dst",
            "port",
            "verdict",
            "reason",
            "detail",
            "outcome",
            "names",
            "bytes_up",
            "bytes_down",
            "name",
            "qtype",
            "rcode",
            "answers",
            "malformed",
        ] {
            assert!(e.get(k).is_some(), "{k}");
        }
    }
}
