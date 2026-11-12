//! The encrypted, resumable transfer between two Macs on the local network.
//!
//! Handshake (initiator = sender, responder = receiver), over plain TCP:
//!
//! 1. I → R: `MACPACK2`, a 16-byte transfer id to resume (zeros for none), and SHA-256 of I's
//!    ephemeral X25519 public key (a commitment).
//! 2. R → I: `MACPACK2`, one byte saying whether R knows that transfer, and R's ephemeral key.
//! 3. I → R: I's public key; R checks it against the commitment.
//!
//! Both sides derive two ChaCha20-Poly1305 keys (one per direction) with HKDF from the X25519
//! shared secret, the transcript, and (when resuming) the transfer's resume secret, plus a
//! 6-digit code. For a new transfer each Mac shows the code and the receiver accepts only when
//! they match: someone in the middle would hold different keys with each side, and the
//! commitment stops them from searching for keys that make the codes collide.
//!
//! Once accepted, both sides keep a resume secret derived from that first channel. Reconnects
//! mix it into the keys, so they need no new code and can't be taken over by anyone who wasn't
//! part of the original, verified exchange.
//!
//! The package is one gzipped tar stream, cut into parts of about 16 MB as it's packed. Each
//! finished part is sent (and checked against its SHA-256) while the next one is still being
//! packed, so packing and sending overlap. The receiver appends verified parts to
//! `inbox/<id>.part` and files the package once the last one arrives. A dropped or stalled
//! connection is retried with backoff and resumes at the byte where it stopped, within the
//! part it was on.
//!
//! After the handshake every message is a frame: a big-endian `u32` length, then ciphertext
//! whose first plaintext byte says what it is (JSON control message, file data, or end).

use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::package::{self, Manifest};

const MAGIC: &[u8; 8] = b"MACPACK2";
const MAX_FRAME: usize = 4 << 20;
const CHUNK: usize = 256 << 10;
/// How long the sender waits for the person at the other Mac to accept.
const DECISION_TIMEOUT: Duration = Duration::from_secs(600);
/// A transfer that moves nothing for this long is treated as dropped and retried.
const STALL: Duration = Duration::from_secs(45);
/// Retries before the sender gives up.
pub const MAX_ATTEMPTS: u32 = 30;

const KIND_JSON: u8 = 0;
const KIND_DATA: u8 = 1;
const KIND_END: u8 = 2;

/// The port macpack listens on, so an address can be typed by hand when discovery fails.
/// Another program holding it makes macpack fall back to a random port.
pub const PORT: u16 = 47_321;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Msg {
    /// A new transfer, on a channel the receiver hasn't verified yet. Sent before packing
    /// starts producing anything, so the other Mac can accept straight away.
    Offer {
        id: String,
        from: String,
        manifest: Manifest,
    },
    /// Continue transfer `id`, on a channel keyed with its resume secret.
    Resume {
        id: String,
    },
    /// Accepted (an offer or a resume), or: send part data from this byte of the part.
    Accept {
        offset: u64,
    },
    Decline {
        reason: String,
    },
    /// The sender is packing; this is how far it got.
    Status {
        label: String,
        index: usize,
        total: usize,
        packed: u64,
    },
    /// Part `index` is next: this big, with this hash.
    Part {
        index: usize,
        size: u64,
        sha256: String,
    },
    /// The part arrived and checked out.
    PartOk,
    /// That was all of it: `parts` parts, `size` bytes.
    Finish {
        parts: usize,
        size: u64,
    },
    Received,
    /// A part didn't check out; the receiver threw it away.
    Corrupt,
    /// Asks who's there, without involving the user.
    Ping,
    Pong {
        name: String,
        version: String,
    },
}

/// Parts are cut once they pass this size.
const PART_SIZE: u64 = 16 << 20;

pub type TransferId = [u8; 16];

pub fn new_id() -> TransferId {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("system randomness");
    b
}

pub fn id_hex(id: &TransferId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub struct Channel {
    stream: TcpStream,
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_n: u64,
    recv_n: u64,
    /// The 6-digit verification code both sides show.
    pub code: String,
    /// Keyed with a known transfer's resume secret.
    pub resumed: bool,
    /// The secret later reconnects of a transfer accepted on this channel use.
    resume_secret: [u8; 32],
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("system randomness");
    b
}

fn nonce(n: u64) -> Nonce {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_be_bytes());
    *Nonce::from_slice(&b)
}

struct Keys {
    i2r: [u8; 32],
    r2i: [u8; 32],
    code: String,
    resume: [u8; 32],
}

fn derive(
    shared: &[u8; 32],
    id: &TransferId,
    i_pub: &[u8; 32],
    r_pub: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Keys {
    let mut t = Sha256::new();
    t.update(MAGIC);
    t.update(id);
    t.update(i_pub);
    t.update(r_pub);
    let transcript = t.finalize();
    let mut ikm = shared.to_vec();
    if let Some(psk) = psk {
        ikm.extend_from_slice(psk);
    }
    let hk = Hkdf::<Sha256>::new(Some(&transcript), &ikm);
    let mut k = Keys {
        i2r: [0; 32],
        r2i: [0; 32],
        code: String::new(),
        resume: [0; 32],
    };
    let mut sas = [0u8; 4];
    hk.expand(b"macpack i2r", &mut k.i2r).expect("hkdf");
    hk.expand(b"macpack r2i", &mut k.r2i).expect("hkdf");
    hk.expand(b"macpack code", &mut sas).expect("hkdf");
    hk.expand(b"macpack resume", &mut k.resume).expect("hkdf");
    let n = u32::from_be_bytes(sas) % 1_000_000;
    k.code = format!("{:03} {:03}", n / 1000, n % 1000);
    k
}

fn read_exact<const N: usize>(s: &mut TcpStream) -> Result<[u8; N]> {
    let mut b = [0u8; N];
    s.read_exact(&mut b)?;
    Ok(b)
}

impl Channel {
    /// `resume`: a transfer to continue and its resume secret.
    pub fn initiate(
        mut stream: TcpStream,
        resume: Option<(&TransferId, &[u8; 32])>,
    ) -> Result<Channel> {
        let id = resume.map(|r| *r.0).unwrap_or_default();
        let secret = StaticSecret::from(random32());
        let mine = PublicKey::from(&secret).to_bytes();
        stream.write_all(MAGIC)?;
        stream.write_all(&id)?;
        stream.write_all(&Sha256::digest(mine))?;
        if &read_exact::<8>(&mut stream)? != MAGIC {
            bail!("the other Mac runs an incompatible macpack; update both");
        }
        let known = read_exact::<1>(&mut stream)?[0] == 1;
        let theirs = read_exact::<32>(&mut stream)?;
        stream.write_all(&mine)?;
        let shared = secret.diffie_hellman(&PublicKey::from(theirs)).to_bytes();
        let psk = resume.filter(|_| known).map(|r| r.1);
        let k = derive(&shared, &id, &mine, &theirs, psk);
        Ok(Channel::new(stream, k.i2r, k.r2i, k, psk.is_some()))
    }

    /// `lookup` finds the resume secret of a transfer this Mac knows.
    pub fn respond(
        mut stream: TcpStream,
        lookup: impl Fn(&TransferId) -> Option<[u8; 32]>,
    ) -> Result<Channel> {
        if &read_exact::<8>(&mut stream)? != MAGIC {
            bail!("not a macpack connection");
        }
        let id = read_exact::<16>(&mut stream)?;
        let commitment = read_exact::<32>(&mut stream)?;
        let psk = (id != [0; 16]).then(|| lookup(&id)).flatten();
        let secret = StaticSecret::from(random32());
        let mine = PublicKey::from(&secret).to_bytes();
        stream.write_all(MAGIC)?;
        stream.write_all(&[psk.is_some() as u8])?;
        stream.write_all(&mine)?;
        let theirs = read_exact::<32>(&mut stream)?;
        if Sha256::digest(theirs).as_slice() != commitment {
            bail!("handshake commitment didn't match");
        }
        let shared = secret.diffie_hellman(&PublicKey::from(theirs)).to_bytes();
        let k = derive(&shared, &id, &theirs, &mine, psk.as_ref());
        Ok(Channel::new(stream, k.r2i, k.i2r, k, psk.is_some()))
    }

    fn new(stream: TcpStream, send: [u8; 32], recv: [u8; 32], k: Keys, resumed: bool) -> Channel {
        Channel {
            stream,
            send: ChaCha20Poly1305::new(Key::from_slice(&send)),
            recv: ChaCha20Poly1305::new(Key::from_slice(&recv)),
            send_n: 0,
            recv_n: 0,
            code: k.code,
            resumed,
            resume_secret: k.resume,
        }
    }

    fn send_frame(&mut self, kind: u8, data: &[u8]) -> Result<()> {
        let mut plain = Vec::with_capacity(data.len() + 1);
        plain.push(kind);
        plain.extend_from_slice(data);
        let ct = self
            .send
            .encrypt(&nonce(self.send_n), plain.as_slice())
            .map_err(|_| anyhow!("encrypt"))?;
        self.send_n += 1;
        self.stream.write_all(&(ct.len() as u32).to_be_bytes())?;
        self.stream.write_all(&ct)?;
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        let len = u32::from_be_bytes(read_exact::<4>(&mut self.stream)?) as usize;
        if len > MAX_FRAME + 64 {
            bail!("frame too large");
        }
        let mut ct = vec![0u8; len];
        self.stream.read_exact(&mut ct)?;
        let mut plain = self
            .recv
            .decrypt(&nonce(self.recv_n), ct.as_slice())
            .map_err(|_| anyhow!("couldn't decrypt: the connection was tampered with"))?;
        self.recv_n += 1;
        if plain.is_empty() {
            bail!("empty frame");
        }
        let kind = plain.remove(0);
        Ok((kind, plain))
    }

    fn send_msg(&mut self, m: &Msg) -> Result<()> {
        self.send_frame(KIND_JSON, &serde_json::to_vec(m)?)
    }

    fn recv_msg(&mut self) -> Result<Msg> {
        match self.recv_frame()? {
            (KIND_JSON, b) => Ok(serde_json::from_slice(&b)?),
            _ => bail!("expected a control message"),
        }
    }
}

fn friendly(e: &anyhow::Error) -> String {
    let s = format!("{e:#}");
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        use std::io::ErrorKind::*;
        let what = match io.kind() {
            WouldBlock | TimedOut => "the connection stalled",
            ConnectionRefused => "the other Mac refused the connection (is macpack open?)",
            ConnectionReset | ConnectionAborted | BrokenPipe => "the connection dropped",
            UnexpectedEof => "the other Mac closed the connection",
            HostUnreachable | NetworkUnreachable => "the other Mac isn't reachable",
            _ => return s,
        };
        return format!("{what} ({io})");
    }
    s
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex32(&h.finalize().into()))
}

// ------------------------------------------------------------------------------------ sending

/// What the sender sees while a transfer runs.
#[derive(Debug, Clone, PartialEq)]
pub enum SendEvent {
    /// Packing item `index` of `total` (`~/.ssh`).
    Packing {
        label: String,
        index: usize,
        total: usize,
    },
    /// Compressed bytes packed so far.
    Packed(u64),
    /// Packing finished: the package is this big.
    PackDone {
        size: u64,
    },
    Connecting {
        attempt: u32,
    },
    /// Connected to a Mac that hasn't accepted yet: show this code.
    Code(String),
    /// The other Mac accepted (or recognised a reconnect).
    Accepted {
        resumed: bool,
    },
    /// Picked up where an earlier attempt stopped, this many bytes in.
    Resumed(u64),
    /// Bytes delivered and checked so far, plus the part in flight.
    Progress(u64),
    /// All parts delivered; the other Mac is filing the package.
    Verifying,
    /// `error` happened; trying again in `wait` seconds.
    Retrying {
        attempt: u32,
        error: String,
        wait: u64,
    },
    Note(String),
}

/// A finished part waiting to be sent.
#[derive(Clone)]
struct PartFile {
    path: PathBuf,
    size: u64,
    sha256: String,
}

/// Packing progress, shared between the packing thread and the connection.
#[derive(Default)]
struct PackState {
    label: String,
    index: usize,
    total: usize,
    packed: u64,
    parts: Vec<PartFile>,
    /// Number of parts once packing finished, or why it failed.
    done: Option<std::result::Result<usize, String>>,
}

/// Writes a stream into numbered part files, hashing each, and publishes every part as it's
/// cut so it can be sent while the rest is still being written.
struct PartWriter {
    dir: PathBuf,
    state: std::sync::Arc<std::sync::Mutex<PackState>>,
    file: Option<std::io::BufWriter<std::fs::File>>,
    hash: Sha256,
    size: u64,
    index: usize,
}

impl PartWriter {
    fn path(&self, i: usize) -> PathBuf {
        self.dir.join(format!("{i:05}.part"))
    }

    fn close(&mut self) -> std::io::Result<()> {
        let Some(mut f) = self.file.take() else {
            return Ok(());
        };
        f.flush()?;
        let hash = std::mem::take(&mut self.hash);
        let part = PartFile {
            path: self.path(self.index),
            size: self.size,
            sha256: hex32(&hash.finalize().into()),
        };
        self.state.lock().unwrap().parts.push(part);
        self.index += 1;
        self.size = 0;
        Ok(())
    }
}

impl Write for PartWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.file.is_none() {
            let f = std::fs::File::create(self.path(self.index))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            self.file = Some(std::io::BufWriter::new(f));
        }
        let n = self.file.as_mut().unwrap().write(buf)?;
        self.hash.update(&buf[..n]);
        self.size += n as u64;
        if self.size >= PART_SIZE {
            self.close()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.file {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

/// A package being packed and sent, with what's needed to resume it.
pub struct Outgoing {
    pub id: TransferId,
    dir: PathBuf,
    pub from: String,
    pub manifest: Manifest,
    state: std::sync::Arc<std::sync::Mutex<PackState>>,
    /// Set once the receiver accepted: reconnects use it instead of a new code.
    resume: Option<[u8; 32]>,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Outgoing {
    /// Starts packing in the background; parts become sendable as they're cut.
    pub fn start(
        from: String,
        manifest: Manifest,
        on: std::sync::Arc<dyn Fn(SendEvent) + Send + Sync>,
    ) -> Result<Outgoing> {
        let id = new_id();
        let outbox = crate::store::data_dir().join("outbox");
        let dir = outbox.join(id_hex(&id));
        std::fs::create_dir_all(&dir).context("create the outbox")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&outbox, std::fs::Permissions::from_mode(0o700))?;
        }
        let state = std::sync::Arc::new(std::sync::Mutex::new(PackState::default()));
        let mut w = PartWriter {
            dir: dir.clone(),
            state: state.clone(),
            file: None,
            hash: Sha256::new(),
            size: 0,
            index: 0,
        };
        let (st, items) = (state.clone(), manifest.items.clone());
        std::thread::spawn(move || {
            let total = items.iter().filter(|i| i.kind.has_files()).count();
            let index = std::cell::Cell::new(0usize);
            let res = package::write_files(
                &items,
                &mut w,
                |_, it| {
                    index.set(index.get() + 1);
                    {
                        let mut g = st.lock().unwrap();
                        g.label = it.label.clone();
                        g.index = index.get();
                        g.total = total;
                    }
                    on(SendEvent::Packing {
                        label: it.label.clone(),
                        index: index.get(),
                        total,
                    });
                },
                |n| {
                    st.lock().unwrap().packed = n;
                    on(SendEvent::Packed(n));
                },
            )
            .and_then(|_| Ok(w.close()?));
            let mut g = st.lock().unwrap();
            match res {
                Ok(()) => {
                    let size = g.parts.iter().map(|p| p.size).sum();
                    g.done = Some(Ok(g.parts.len()));
                    drop(g);
                    on(SendEvent::PackDone { size });
                }
                Err(e) => g.done = Some(Err(format!("{e:#}"))),
            }
        });
        Ok(Outgoing {
            id,
            dir,
            from,
            manifest,
            state,
            resume: None,
        })
    }
}

enum Attempt {
    Sent,
    Declined(String),
}

#[derive(Debug)]
struct PackFailed(String);

impl std::fmt::Display for PackFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "packing failed: {}", self.0)
    }
}

impl std::error::Error for PackFailed {}

/// Sends `out` to `addr`, retrying with backoff and resuming after drops. Returns `Ok(false)`
/// when the other Mac declined. `cancel` stops it; `retry_now` cuts a backoff wait short.
pub fn send(
    addr: SocketAddr,
    out: &mut Outgoing,
    cancel: &AtomicBool,
    retry_now: &AtomicBool,
    on: &dyn Fn(SendEvent),
) -> Result<bool> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        if cancel.load(Ordering::Relaxed) {
            bail!("cancelled");
        }
        on(SendEvent::Connecting { attempt });
        match try_send(addr, out, cancel, on) {
            Ok(Attempt::Sent) => return Ok(true),
            Ok(Attempt::Declined(reason)) => {
                on(SendEvent::Note(reason));
                return Ok(false);
            }
            Err(e) if cancel.load(Ordering::Relaxed) => return Err(e.context("cancelled")),
            Err(e) if e.downcast_ref::<PackFailed>().is_some() => return Err(e),
            Err(e) if attempt >= MAX_ATTEMPTS => {
                return Err(anyhow!(
                    "gave up after {attempt} attempts: {}",
                    friendly(&e)
                ));
            }
            Err(e) => {
                let wait = (1u64 << attempt.min(5)).min(30);
                on(SendEvent::Retrying {
                    attempt,
                    error: friendly(&e),
                    wait,
                });
                retry_now.store(false, Ordering::Relaxed);
                for _ in 0..wait * 5 {
                    if cancel.load(Ordering::Relaxed) {
                        bail!("cancelled");
                    }
                    if retry_now.swap(false, Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
}

/// What to do next: send part `n`, or finish with this many parts.
enum Next {
    Part(PartFile),
    Finish(usize),
}

fn try_send(
    addr: SocketAddr,
    out: &mut Outgoing,
    cancel: &AtomicBool,
    on: &dyn Fn(SendEvent),
) -> Result<Attempt> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .with_context(|| format!("connect to {addr}"))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(STALL))?;
    stream.set_write_timeout(Some(STALL))?;
    let resume = out.resume;
    let mut ch = Channel::initiate(stream, resume.as_ref().map(|r| (&out.id, r)))?;
    if ch.resumed {
        ch.send_msg(&Msg::Resume {
            id: id_hex(&out.id),
        })?;
        match ch.recv_msg()? {
            Msg::Accept { .. } => on(SendEvent::Accepted { resumed: true }),
            Msg::Decline { reason } => return Ok(Attempt::Declined(reason)),
            m => bail!("unexpected reply {m:?}"),
        }
    } else {
        if resume.is_some() {
            on(SendEvent::Note(
                "The other Mac lost track of this transfer; it needs accepting again".into(),
            ));
            out.resume = None;
        }
        on(SendEvent::Code(ch.code.clone()));
        ch.send_msg(&Msg::Offer {
            id: id_hex(&out.id),
            from: out.from.clone(),
            manifest: out.manifest.clone(),
        })?;
        ch.stream.set_read_timeout(Some(DECISION_TIMEOUT))?;
        let reply = ch.recv_msg()?;
        ch.stream.set_read_timeout(Some(STALL))?;
        match reply {
            Msg::Accept { .. } => {
                out.resume = Some(ch.resume_secret);
                on(SendEvent::Accepted { resumed: false });
            }
            Msg::Decline { reason } => return Ok(Attempt::Declined(reason)),
            m => bail!("unexpected reply {m:?}"),
        }
    }

    // Parts are offered in order; the receiver skips ones it already has.
    let mut delivered = 0u64;
    let mut index = 0usize;
    let mut first = true;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let next = loop {
            if cancel.load(Ordering::Relaxed) {
                bail!("cancelled");
            }
            let status = {
                let g = out.state.lock().unwrap();
                if let Some(p) = g.parts.get(index) {
                    break Next::Part(p.clone());
                }
                match &g.done {
                    Some(Ok(n)) => break Next::Finish(*n),
                    Some(Err(e)) => return Err(PackFailed(e.clone()).into()),
                    None => Msg::Status {
                        label: g.label.clone(),
                        index: g.index,
                        total: g.total,
                        packed: g.packed,
                    },
                }
            };
            // Keeps the other Mac posted (and the connection alive) while packing catches up.
            ch.send_msg(&status)?;
            std::thread::sleep(Duration::from_millis(300));
        };
        let part = match next {
            Next::Part(p) => p,
            Next::Finish(parts) => {
                ch.send_msg(&Msg::Finish {
                    parts,
                    size: delivered,
                })?;
                on(SendEvent::Verifying);
                ch.stream.set_read_timeout(Some(Duration::from_secs(120)))?;
                return match ch.recv_msg()? {
                    Msg::Received => Ok(Attempt::Sent),
                    m => bail!("unexpected reply {m:?}"),
                };
            }
        };
        ch.send_msg(&Msg::Part {
            index,
            size: part.size,
            sha256: part.sha256.clone(),
        })?;
        let offset = match ch.recv_msg()? {
            Msg::Accept { offset } => offset.min(part.size),
            Msg::Decline { reason } => return Ok(Attempt::Declined(reason)),
            m => bail!("unexpected reply {m:?}"),
        };
        let already = delivered + offset;
        if first && already > 0 {
            on(SendEvent::Resumed(already));
        }
        if offset < part.size {
            first = false;
            let mut f = std::fs::File::open(&part.path)?;
            f.seek(SeekFrom::Start(offset))?;
            let mut sent = offset;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    bail!("cancelled");
                }
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                ch.send_frame(KIND_DATA, &buf[..n])?;
                sent += n as u64;
                on(SendEvent::Progress(delivered + sent));
            }
            ch.send_frame(KIND_END, &[])?;
            match ch.recv_msg()? {
                Msg::PartOk => {}
                Msg::Corrupt => bail!("part {} arrived damaged; sending it again", index + 1),
                m => bail!("unexpected reply {m:?}"),
            }
        }
        delivered += part.size;
        on(SendEvent::Progress(delivered));
        // Delivered and checked: the receiver has it on disk, so the copy here can go.
        let _ = std::fs::remove_file(&part.path);
        index += 1;
    }
}

/// Checks that macpack answers at `addr`, returning its name and version.
pub fn ping(addr: SocketAddr) -> Result<(String, String)> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .with_context(|| format!("nothing answered at {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut ch = Channel::initiate(stream, None).context("that isn't macpack")?;
    ch.send_msg(&Msg::Ping)?;
    match ch.recv_msg()? {
        Msg::Pong { name, version } => Ok((name, version)),
        m => bail!("unexpected reply {m:?}"),
    }
}

/// `192.168.1.20`, `192.168.1.20:47321` or `macbook.local` → a socket address, using
/// macpack's port when none is given.
pub fn parse_addr(input: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, PORT));
    }
    let with_port = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:{PORT}")
    };
    with_port.to_socket_addrs().ok()?.find(|a| a.is_ipv4())
}

/// Finds macpack on every host of the /24 networks of `mine` (this Mac's addresses) by
/// pinging [`PORT`]. Hosts that don't answer cost a short connect timeout; takes a few seconds.
pub fn sweep(mine: &[std::net::Ipv4Addr]) -> Vec<crate::discovery::Peer> {
    let targets: Vec<SocketAddr> = mine
        .iter()
        .flat_map(|ip| {
            let [a, b, c, _] = ip.octets();
            (1..255u8).map(move |d| std::net::Ipv4Addr::new(a, b, c, d))
        })
        .filter(|ip| !mine.contains(ip))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|ip| SocketAddr::new(ip.into(), PORT))
        .collect();
    std::thread::scope(|sc| {
        let hs: Vec<_> = targets
            .chunks(4)
            .map(|chunk| {
                sc.spawn(move || {
                    chunk
                        .iter()
                        .filter_map(|&addr| {
                            // A bare connect first: most addresses refuse or time out fast.
                            // Only a full ping (which the other side answers quietly) counts.
                            TcpStream::connect_timeout(&addr, Duration::from_millis(400)).ok()?;
                            let (name, _) = ping(addr).ok()?;
                            Some(crate::discovery::Peer {
                                id: format!("lan:{addr}"),
                                name,
                                addr,
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    })
}

/// This Mac's LAN addresses, to show so the other Mac can type one in.
pub fn local_ips() -> Vec<std::net::Ipv4Addr> {
    let mut out = Vec::new();
    for ifc in ["en0", "en1", "en2", "en3", "en4", "en5", "en6"] {
        let Ok(o) = std::process::Command::new("/usr/sbin/ipconfig")
            .args(["getifaddr", ifc])
            .output()
        else {
            continue;
        };
        if let Ok(ip) = String::from_utf8_lossy(&o.stdout).trim().parse()
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

// ---------------------------------------------------------------------------------- receiving

/// An incoming offer, waiting for the user.
pub struct Offer {
    pub id: String,
    pub from: String,
    pub code: String,
    pub manifest: Manifest,
}

/// What the receiver sees while a transfer runs.
#[derive(Debug, Clone)]
pub enum RecvEvent {
    /// Connected (or reconnected) to transfer `id` from `from`; `have` bytes are already here.
    Connected {
        id: String,
        from: String,
        resumed: bool,
        have: u64,
    },
    /// The sender is packing; `packed` bytes so far.
    Packing {
        id: String,
        label: String,
        index: usize,
        total: usize,
        packed: u64,
    },
    /// Bytes received so far, across all parts.
    Progress {
        id: String,
        received: u64,
    },
    /// All parts arrived: `size` bytes.
    Finishing {
        id: String,
        size: u64,
    },
    /// The connection dropped; the sender will reconnect and resume.
    Interrupted {
        id: String,
        error: String,
    },
    /// A part was damaged and thrown away; the sender sends it again.
    Corrupt {
        id: String,
    },
    Done {
        id: String,
        saved: Saved,
    },
}

/// Callbacks a receiving Mac uses to involve the user.
pub trait Receiver: Send + Sync + 'static {
    /// Blocks until the user accepts or declines.
    fn decide(&self, offer: Offer) -> bool;
    fn event(&self, e: RecvEvent);
    /// This Mac's name, for answering pings.
    fn name(&self) -> String;
}

/// A package saved in the inbox.
#[derive(Debug, Clone)]
pub struct Saved {
    pub id: String,
    pub manifest: Manifest,
}

/// An accepted transfer still arriving: `inbox/<id>.meta.json`, beside `<id>.part`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    from: String,
    manifest: Manifest,
    resume: String,
    /// Parts appended to `<id>.part` so far, and its length after them.
    #[serde(default)]
    parts_done: usize,
    #[serde(default)]
    assembled: u64,
}

pub fn inbox() -> PathBuf {
    crate::store::data_dir().join("inbox")
}

pub fn package_path(id: &str) -> PathBuf {
    inbox().join(format!("{id}.tar.gz"))
}

fn part_path(id: &str) -> PathBuf {
    inbox().join(format!("{id}.part"))
}

/// The part currently arriving.
fn current_path(id: &str) -> PathBuf {
    inbox().join(format!("{id}.cur"))
}

fn meta_path(id: &str) -> PathBuf {
    inbox().join(format!("{id}.meta.json"))
}

fn load_pending(id: &str) -> Option<Pending> {
    serde_json::from_slice(&std::fs::read(meta_path(id)).ok()?).ok()
}

/// Stops an incoming transfer and throws away what arrived. A sender that reconnects is told
/// it was cancelled.
pub fn discard(id: &str) {
    let _ = std::fs::remove_file(meta_path(id));
    let _ = std::fs::remove_file(part_path(id));
    let _ = std::fs::remove_file(current_path(id));
}

/// Packages received earlier, newest first.
pub fn saved() -> Vec<Saved> {
    let mut out: Vec<Saved> = std::fs::read_dir(inbox())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let id = name.strip_suffix(".json")?.to_string();
            if id.ends_with(".meta") || !package_path(&id).exists() {
                return None;
            }
            let manifest = serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()?;
            Some(Saved { id, manifest })
        })
        .collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.manifest.created));
    out
}

pub fn delete_saved(id: &str) {
    let _ = std::fs::remove_file(package_path(id));
    let _ = std::fs::remove_file(inbox().join(format!("{id}.json")));
}

/// Listens in the background, returning the port.
pub fn listen(rx: std::sync::Arc<dyn Receiver>) -> Result<u16> {
    let listener = TcpListener::bind(("0.0.0.0", PORT))
        .or_else(|_| TcpListener::bind(("0.0.0.0", 0)))
        .context("listen")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let rx = rx.clone();
            std::thread::spawn(move || {
                // Errors before a transfer starts (port probes, pings that hang up, stray
                // connections) are nobody's business; ones during a transfer are reported.
                if let Err(e) = receive(stream, &*rx) {
                    eprintln!("macpack: incoming connection: {e:#}");
                }
            });
        }
    });
    Ok(port)
}

fn receive(stream: TcpStream, rx: &dyn Receiver) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_nodelay(true)?;
    let mut ch = Channel::respond(stream, |id| {
        load_pending(&id_hex(id)).and_then(|p| unhex::<32>(&p.resume))
    })?;
    let (id, mut pending, resumed) = match ch.recv_msg()? {
        Msg::Ping => {
            ch.send_msg(&Msg::Pong {
                name: rx.name(),
                version: env!("CARGO_PKG_VERSION").into(),
            })?;
            return Ok(());
        }
        Msg::Resume { id } if ch.resumed => match load_pending(&id) {
            Some(p) => (id, p, true),
            None => {
                ch.send_msg(&Msg::Decline {
                    reason: "The transfer was cancelled on the other Mac".into(),
                })?;
                return Ok(());
            }
        },
        Msg::Offer { id, from, manifest } if !ch.resumed => {
            if unhex::<16>(&id).is_none() {
                bail!("bad transfer id");
            }
            if manifest.format > package::FORMAT {
                ch.send_msg(&Msg::Decline {
                    reason: "This Mac runs an older macpack; update it first".into(),
                })?;
                return Ok(());
            }
            let accepted = rx.decide(Offer {
                id: id.clone(),
                from: from.clone(),
                code: ch.code.clone(),
                manifest: manifest.clone(),
            });
            if !accepted {
                ch.send_msg(&Msg::Decline {
                    reason: "The other Mac declined".into(),
                })?;
                return Ok(());
            }
            let p = Pending {
                from,
                manifest,
                resume: hex32(&ch.resume_secret),
                parts_done: 0,
                assembled: 0,
            };
            std::fs::create_dir_all(inbox())?;
            write_private(&meta_path(&id), &serde_json::to_vec(&p)?)?;
            (id, p, false)
        }
        m => bail!("unexpected {m:?}"),
    };
    // Undo an append that happened after the last saved state (a crash between the two).
    let assembled = part_path(&id);
    {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&assembled)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        if f.metadata()?.len() != pending.assembled {
            f.set_len(pending.assembled)?;
        }
    }
    let cur = current_path(&id);
    let have = pending.assembled + std::fs::metadata(&cur).map(|m| m.len()).unwrap_or(0);
    ch.send_msg(&Msg::Accept { offset: 0 })?;
    rx.event(RecvEvent::Connected {
        id: id.clone(),
        from: pending.from.clone(),
        resumed,
        have,
    });
    ch.stream.set_read_timeout(Some(STALL))?;
    let res = (|| -> Result<Option<usize>> {
        loop {
            match ch.recv_msg()? {
                Msg::Status {
                    label,
                    index,
                    total,
                    packed,
                } => {
                    rx.event(RecvEvent::Packing {
                        id: id.clone(),
                        label,
                        index,
                        total,
                        packed,
                    });
                    if !meta_path(&id).exists() {
                        bail!("cancelled on this Mac");
                    }
                }
                Msg::Part {
                    index,
                    size,
                    sha256,
                } => {
                    if index < pending.parts_done {
                        ch.send_msg(&Msg::Accept { offset: size })?;
                        continue;
                    }
                    if index > pending.parts_done {
                        bail!("part {index} came before part {}", pending.parts_done);
                    }
                    let mut f = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&cur)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                    }
                    let offset = f.metadata()?.len().min(size);
                    f.set_len(offset)?;
                    ch.send_msg(&Msg::Accept { offset })?;
                    let mut got = offset;
                    let mut frames = 0u32;
                    loop {
                        match ch.recv_frame()? {
                            (KIND_DATA, b) => {
                                f.write_all(&b)?;
                                got += b.len() as u64;
                                rx.event(RecvEvent::Progress {
                                    id: id.clone(),
                                    received: pending.assembled + got,
                                });
                                frames += 1;
                                if frames.is_multiple_of(32) && !meta_path(&id).exists() {
                                    bail!("cancelled on this Mac");
                                }
                            }
                            (KIND_END, _) => break,
                            _ => bail!("unexpected message during transfer"),
                        }
                    }
                    f.sync_all()?;
                    drop(f);
                    if got != size || sha256_file(&cur)? != sha256 {
                        let _ = std::fs::remove_file(&cur);
                        ch.send_msg(&Msg::Corrupt)?;
                        rx.event(RecvEvent::Corrupt { id: id.clone() });
                        continue;
                    }
                    // Append the checked part to the package, then record that it's there.
                    let mut a = std::fs::OpenOptions::new().append(true).open(&assembled)?;
                    std::io::copy(&mut std::fs::File::open(&cur)?, &mut a)?;
                    a.sync_all()?;
                    pending.parts_done += 1;
                    pending.assembled += size;
                    write_private(&meta_path(&id), &serde_json::to_vec(&pending)?)?;
                    let _ = std::fs::remove_file(&cur);
                    ch.send_msg(&Msg::PartOk)?;
                }
                Msg::Finish { parts, size } => {
                    if parts != pending.parts_done || size != pending.assembled {
                        bail!(
                            "expected {parts} parts ({size} bytes), have {} ({} bytes)",
                            pending.parts_done,
                            pending.assembled
                        );
                    }
                    rx.event(RecvEvent::Finishing {
                        id: id.clone(),
                        size,
                    });
                    return Ok(Some(parts));
                }
                m => bail!("unexpected {m:?}"),
            }
        }
    })();
    if let Err(e) = res {
        rx.event(RecvEvent::Interrupted {
            id: id.clone(),
            error: friendly(&e),
        });
        return Err(e);
    }
    std::fs::rename(&assembled, package_path(&id))?;
    write_private(
        &inbox().join(format!("{id}.json")),
        &serde_json::to_vec_pretty(&pending.manifest)?,
    )?;
    let _ = std::fs::remove_file(meta_path(&id));
    let _ = ch.send_msg(&Msg::Received);
    rx.event(RecvEvent::Done {
        id: id.clone(),
        saved: Saved {
            id,
            manifest: pending.manifest,
        },
    });
    Ok(())
}

/// The inbox holds SSH keys and credentials: owner-only.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        if let Some(dir) = path.parent() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Item, Kind};
    use std::sync::Mutex;
    use std::sync::mpsc;

    struct Auto {
        code: Mutex<String>,
        events: Mutex<mpsc::Sender<RecvEvent>>,
    }

    impl Receiver for Auto {
        fn decide(&self, offer: Offer) -> bool {
            *self.code.lock().unwrap() = offer.code;
            offer.from == "laptop"
        }
        fn event(&self, e: RecvEvent) {
            let _ = self.events.lock().unwrap().send(e);
        }
        fn name(&self) -> String {
            "desk".into()
        }
    }

    fn manifest() -> Manifest {
        Manifest::new(
            "laptop".into(),
            vec![Item {
                kind: Kind::Cask,
                id: "signal".into(),
                label: "Signal".into(),
                detail: String::new(),
                size: None,
                size_over: false,
                default_on: true,
                sensitive: false,
            }],
        )
    }

    /// Forwards TCP to `to`, cutting the first connection after `cut` bytes from the sender,
    /// like a Wi-Fi drop mid-transfer.
    fn flaky_proxy(to: SocketAddr, cut: usize) -> SocketAddr {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for (n, client) in l.incoming().flatten().enumerate() {
                let server = TcpStream::connect(to).unwrap();
                let (mut c2, mut s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut s2, &mut c2);
                });
                let limit = if n == 0 { cut } else { usize::MAX };
                std::thread::spawn(move || {
                    let (mut client, mut server) = (client, server);
                    let mut buf = [0u8; 8192];
                    let mut total = 0;
                    while let Ok(k) = client.read(&mut buf) {
                        if k == 0 {
                            break;
                        }
                        let k = k.min(limit - total);
                        if server.write_all(&buf[..k]).is_err() {
                            break;
                        }
                        total += k;
                        if total >= limit {
                            let _ = client.shutdown(std::net::Shutdown::Both);
                            let _ = server.shutdown(std::net::Shutdown::Both);
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// A package (made bigger with random padding) sent through a connection that drops
    /// partway: the sender retries, resumes without a new code, and the receiver ends up with
    /// the exact file.
    #[test]
    fn resumes_after_a_dropped_connection() {
        let tmp = std::env::temp_dir().join(format!("macpack-net-{}", std::process::id()));
        // SAFETY: tests in this module are the only ones touching XDG_DATA_HOME.
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let (tx, events) = mpsc::channel();
        let port = listen(std::sync::Arc::new(Auto {
            code: Mutex::new(String::new()),
            events: Mutex::new(tx),
        }))
        .unwrap();
        let direct: SocketAddr = ([127, 0, 0, 1], port).into();
        assert_eq!(ping(direct).unwrap().0, "desk");

        let codes = Mutex::new(Vec::new());
        let log = Mutex::new(Vec::new());
        let on = |e: SendEvent| {
            if let SendEvent::Code(c) = &e {
                codes.lock().unwrap().push(c.clone());
            }
            log.lock().unwrap().push(e);
        };
        // 3 MB of noise packs into one ~3 MB part; with parts this small in the test the cut
        // lands mid-stream either way.
        let mut noise = vec![0u8; 3 << 20];
        getrandom::getrandom(&mut noise).unwrap();
        let src = tmp.join("noise.bin");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(&src, &noise).unwrap();
        let mut out =
            Outgoing::start("laptop".into(), manifest(), std::sync::Arc::new(|_| {})).unwrap();
        // Swap the packed output for the noise, split into three parts, as if just packed.
        loop {
            if out.state.lock().unwrap().done.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        {
            let mut g = out.state.lock().unwrap();
            g.parts.clear();
            for (i, chunk) in noise.chunks(1 << 20).enumerate() {
                let path = out.dir.join(format!("t{i}"));
                std::fs::write(&path, chunk).unwrap();
                g.parts.push(PartFile {
                    path,
                    size: chunk.len() as u64,
                    sha256: hex32(&Sha256::digest(chunk).into()),
                });
            }
            g.done = Some(Ok(3));
        }
        // Cut the first connection 1.5 MB in: part 1 is through, part 2 half way.
        let proxy = flaky_proxy(direct, (3 << 20) / 2);
        let (cancel, now) = (AtomicBool::new(false), AtomicBool::new(true));
        assert!(send(proxy, &mut out, &cancel, &now, &on).unwrap());

        let log = log.into_inner().unwrap();
        assert_eq!(codes.lock().unwrap().len(), 1, "a resume needs no new code");
        assert!(log.iter().any(|e| matches!(e, SendEvent::Retrying { .. })));
        assert!(
            log.iter()
                .any(|e| matches!(e, SendEvent::Resumed(n) if *n >= 1 << 20))
        );
        let done = loop {
            match events.recv_timeout(Duration::from_secs(10)).unwrap() {
                RecvEvent::Done { saved, .. } => break saved,
                _ => continue,
            }
        };
        assert_eq!(std::fs::read(package_path(&done.id)).unwrap(), noise);
        assert_eq!(done.manifest, out.manifest);
        assert!(!meta_path(&done.id).exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn hex_round_trips() {
        let id = new_id();
        assert_eq!(unhex::<16>(&id_hex(&id)), Some(id));
        assert_eq!(unhex::<16>("zz"), None);
    }
}
