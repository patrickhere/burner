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
/// how long a new attempt waits for the filter's "let through" before it
/// counts as blocked. both come from the same packet, microseconds apart
const VERDICT_WAIT: Duration = Duration::from_millis(500);

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
        self.settle(now);
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
                    Some(port),
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
            Line::Counts { not_itemized, .. } => self.unlisted(not_itemized),
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
                self.pending.push_back(Try {
                    at: now,
                    flow: (proto, sport, dst, dport),
                    hook,
                    dns,
                });
                // a flood of attempts is cut by the try chain's own limit,
                // this only keeps memory flat if the reader runs ahead
                while self.pending.len() > 4096 {
                    let t = self.pending.pop_front().expect("not empty");
                    self.blocked(t, now);
                }
            }
            "o" | "q" => {
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
                let outcome = match proto {
                    // rst
                    Proto::Tcp if flags & 0x04 != 0 => Outcome::Refused,
                    _ => Outcome::Answered,
                };
                self.outcome((proto, dport, src, sport), outcome);
            }
            "r" => {
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
            return Some(i);
        }
        let full = match verdict {
            Verdict::Allowed => self.allowed_rows >= ROW_CAP,
            Verdict::Blocked => self.blocked_rows >= ROW_CAP,
        };
        if full {
            match verdict {
                Verdict::Allowed => self.allowed_not_itemized += 1,
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

    /// attempts the filter never let out within the wait are blocked
    fn settle(&mut self, now: Instant) {
        while let Some(t) = self.pending.front() {
            if now.saturating_duration_since(t.at) < VERDICT_WAIT {
                break;
            }
            let t = self.pending.pop_front().expect("not empty");
            self.blocked(t, now);
        }
    }

    /// the kernel's verdict was no. the reason is the model's
    fn blocked(&mut self, t: Try, _now: Instant) {
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

    /// the log as it stands once the VM is gone. `extra_lost`: what the
    /// producer side knows it missed, `complete_counts`: the exact counters
    /// were read (linux) or macnet said its counts (mac)
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        mut self,
        id: &str,
        net: &str,
        platform: &str,
        owner: Option<u32>,
        started_unix: u64,
        now: Instant,
        counts_ok: bool,
    ) -> NetLog {
        // nothing more is coming: every attempt still waiting was blocked
        while let Some(t) = self.pending.pop_front() {
            self.blocked(t, now);
        }
        for (i, seen) in self.flows.values() {
            if seen.is_none() && self.rows[*i].outcome.is_none() {
                self.rows[*i].outcome = Some(Outcome::NoAnswer);
            }
        }
        let complete = counts_ok && self.lost == 0 && self.allowed_not_itemized == 0;
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
                .rposition(|e| e.verdict == Verdict::Blocked)
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
    if !log.complete {
        head += ", log incomplete";
        if log.lost > 0 {
            head += &format!(" ({} lost)", log.lost);
        }
    }
    head += &format!(" (burner log {} for all of it)", log.id);
    let mut out = vec![head];
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
    out.into_iter().map(|l| sanitize(&l)).collect()
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
            (Verdict::Blocked, _) => e
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

    fn finish(c: Collector, t0: Instant) -> NetLog {
        c.finish(
            "burner-3fa1c2",
            "web",
            "linux",
            Some(1000),
            0,
            t0 + Duration::from_secs(14),
            true,
        )
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
                dns: 2
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
        assert_eq!(
            l[1],
            "  blocked  tcp 192.168.1.1:22          your lan (192.168.1.0/24 on eth0)   x3"
        );
        assert!(l[2].starts_with("  blocked  tcp 169.254.169.254:80      cloud metadata"));
        assert!(
            l[3].starts_with("  blocked  dns 8.8.8.8 evil.example A  not one of net.resolvers")
        );
        assert_eq!(l.len(), 4);
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
        let log = c.finish("burner-1", "web", "macos", None, 0, t0, true);
        let gh = &log.events[0];
        assert_eq!(
            (gh.outcome, gh.bytes_up, gh.bytes_down),
            (Some(Outcome::Answered), Some(517), Some(4096))
        );
        assert_eq!(log.events[1].reason, Some(Reason::Host));
        assert_eq!(log.events[2].proto, Proto::Icmp);
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
