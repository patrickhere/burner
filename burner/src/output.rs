//! output to the caller goes through a writer thread with a bounded queue, so a
//! reader that stops reading can't stall the main loop (and with it the ttl).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const QUEUE_CAP: usize = 8 << 20;

pub struct Out {
    tx: mpsc::Sender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
    broken: Arc<AtomicBool>,
    dropped: AtomicBool,
    tty: bool,
}

pub enum Dest {
    Stdout,
    Stderr,
}

impl Out {
    pub fn new(dest: Dest) -> Out {
        let fd = match dest {
            Dest::Stdout => 1,
            Dest::Stderr => 2,
        };
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let queued = Arc::new(AtomicUsize::new(0));
        let broken = Arc::new(AtomicBool::new(false));
        let (q, b) = (queued.clone(), broken.clone());
        std::thread::spawn(move || {
            let mut w: Box<dyn Write> = match dest {
                Dest::Stdout => Box::new(std::io::stdout()),
                Dest::Stderr => Box::new(std::io::stderr()),
            };
            for chunk in rx {
                if !b.load(Ordering::Relaxed)
                    && (w.write_all(&chunk).is_err() || w.flush().is_err())
                {
                    b.store(true, Ordering::Relaxed);
                }
                q.fetch_sub(chunk.len(), Ordering::Relaxed);
            }
        });
        Out {
            tx,
            queued,
            broken,
            dropped: AtomicBool::new(false),
            tty: crate::sys::is_tty(fd),
        }
    }

    /// queue bytes. without `wait_until` they're dropped when the queue is full
    pub fn put(&self, b: &[u8], wait_until: Option<Instant>) {
        if b.is_empty() || self.broken.load(Ordering::Relaxed) {
            return;
        }
        let b = if self.tty {
            escape_controls(b)
        } else {
            b.to_vec()
        };
        loop {
            let q = self.queued.load(Ordering::Relaxed);
            if q + b.len() <= QUEUE_CAP {
                self.queued.fetch_add(b.len(), Ordering::Relaxed);
                let _ = self.tx.send(b);
                return;
            }
            if wait_until.is_none_or(|t| Instant::now() > t) || self.broken.load(Ordering::Relaxed)
            {
                self.dropped.store(true, Ordering::Relaxed);
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn drain(&self, until: Instant) {
        while Instant::now() < until {
            if self.queued.load(Ordering::Relaxed) == 0 || self.broken.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// guest bytes must not drive the caller's terminal: control bytes become \xNN
pub fn escape_controls(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    for &c in b {
        if (c < 0x20 && !matches!(c, b'\t' | b'\n' | b'\r')) || c == 0x7f {
            out.extend_from_slice(format!("\\x{c:02x}").as_bytes());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(
            escape_controls(b"a\x1b]52;c;x\x07\n"),
            b"a\\x1b]52;c;x\\x07\n".to_vec()
        );
        assert_eq!(escape_controls(b"tab\there\r\n"), b"tab\there\r\n".to_vec());
    }
}
