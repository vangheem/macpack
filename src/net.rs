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
//! The sender packs everything into a file first, so a transfer can pick up at any byte
//! offset. The receiver appends to `inbox/<id>.part`, checks the size and SHA-256 at the end,
//! and only then files the package. A dropped connection or a stalled one is retried with
//! backoff and resumes where it stopped.
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
    /// A new transfer, on a channel the receiver hasn't verified yet.
    Offer {
        id: String,
        from: String,
        size: u64,
        sha256: String,
        manifest: Manifest,
    },
    /// Continue transfer `id`, on a channel keyed with its resume secret.
    Resume {
        id: String,
    },
    /// Send from this byte on.
    Accept {
        offset: u64,
    },
    Decline {
        reason: String,
    },
    Received,
    /// The finished file didn't check out; the receiver threw it away.
    Corrupt,
    /// Asks who's there, without involving the user.
    Ping,
    Pong {
        name: String,
        version: String,
    },
}

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
    /// Ready: the package is this big.
    PackDone {
        size: u64,
    },
    Connecting {
        attempt: u32,
    },
    /// Connected to a Mac that hasn't accepted yet: show this code.
    Code(String),
    /// Sending from `offset` (non-zero when resuming).
    Sending {
        offset: u64,
        resumed: bool,
    },
    Progress(u64),
    /// Everything sent; the other Mac is checking it.
    Verifying,
    /// `error` happened; trying again in `wait` seconds.
    Retrying {
        attempt: u32,
        error: String,
        wait: u64,
    },
    Note(String),
}

/// A package packed and ready to send, with what's needed to resume it.
pub struct Outgoing {
    pub id: TransferId,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub from: String,
    pub manifest: Manifest,
    /// Set once the receiver accepted: reconnects use it instead of a new code.
    resume: Option<[u8; 32]>,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Packs the manifest's files into the outbox, reporting progress.
pub fn pack(from: String, manifest: Manifest, on: &dyn Fn(SendEvent)) -> Result<Outgoing> {
    let id = new_id();
    let dir = crate::store::data_dir().join("outbox");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.tar.gz", id_hex(&id)));
    let file = std::fs::File::create(&path).context("create the package file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let total = manifest.items.iter().filter(|i| i.kind.has_files()).count();
    let index = std::cell::Cell::new(0usize);
    let w = std::io::BufWriter::new(file);
    let mut out = Outgoing {
        id,
        path: path.clone(),
        size: 0,
        sha256: String::new(),
        from,
        manifest,
        resume: None,
    };
    package::write_files(
        &out.manifest.items,
        w,
        |_, it| {
            index.set(index.get() + 1);
            on(SendEvent::Packing {
                label: it.label.clone(),
                index: index.get(),
                total,
            });
        },
        |n| on(SendEvent::Packed(n)),
    )?;
    out.size = std::fs::metadata(&path)?.len();
    out.sha256 = sha256_file(&path)?;
    on(SendEvent::PackDone { size: out.size });
    Ok(out)
}

enum Attempt {
    Sent,
    Declined(String),
}

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
    let offset = if ch.resumed {
        ch.send_msg(&Msg::Resume {
            id: id_hex(&out.id),
        })?;
        match ch.recv_msg()? {
            Msg::Accept { offset } => offset,
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
            size: out.size,
            sha256: out.sha256.clone(),
            manifest: out.manifest.clone(),
        })?;
        ch.stream.set_read_timeout(Some(DECISION_TIMEOUT))?;
        let reply = ch.recv_msg()?;
        ch.stream.set_read_timeout(Some(STALL))?;
        match reply {
            Msg::Accept { offset } => {
                out.resume = Some(ch.resume_secret);
                offset
            }
            Msg::Decline { reason } => return Ok(Attempt::Declined(reason)),
            m => bail!("unexpected reply {m:?}"),
        }
    };
    if offset > out.size {
        bail!("the other Mac has more than was sent");
    }
    on(SendEvent::Sending {
        offset,
        resumed: offset > 0,
    });
    let mut f = std::fs::File::open(&out.path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; CHUNK];
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
        on(SendEvent::Progress(sent));
    }
    ch.send_frame(KIND_END, &[])?;
    on(SendEvent::Verifying);
    // Hashing a big package takes a while on the other side.
    ch.stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    match ch.recv_msg()? {
        Msg::Received => Ok(Attempt::Sent),
        Msg::Corrupt => bail!("the package arrived damaged; sending it again"),
        m => bail!("unexpected reply {m:?}"),
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
    pub size: u64,
    pub manifest: Manifest,
}

/// What the receiver sees while a transfer runs.
#[derive(Debug, Clone)]
pub enum RecvEvent {
    /// Receiving transfer `id` from `from`, starting at `offset` of `size` bytes.
    Started {
        id: String,
        from: String,
        size: u64,
        offset: u64,
        resumed: bool,
    },
    Progress {
        id: String,
        received: u64,
    },
    Verifying {
        id: String,
    },
    /// The connection dropped; the sender will reconnect and resume.
    Interrupted {
        id: String,
        error: String,
    },
    /// The finished file was damaged and thrown away; the sender sends it again.
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
    size: u64,
    sha256: String,
    manifest: Manifest,
    resume: String,
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
    let (id, pending, resumed) = match ch.recv_msg()? {
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
        Msg::Offer {
            id,
            from,
            size,
            sha256,
            manifest,
        } if !ch.resumed => {
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
                size,
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
                size,
                sha256,
                manifest,
                resume: hex32(&ch.resume_secret),
            };
            std::fs::create_dir_all(inbox())?;
            write_private(&meta_path(&id), &serde_json::to_vec(&p)?)?;
            (id, p, false)
        }
        m => bail!("unexpected {m:?}"),
    };
    let part = part_path(&id);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let offset = f.metadata()?.len().min(pending.size);
    f.set_len(offset)?;
    ch.send_msg(&Msg::Accept { offset })?;
    rx.event(RecvEvent::Started {
        id: id.clone(),
        from: pending.from.clone(),
        size: pending.size,
        offset,
        resumed,
    });
    ch.stream.set_read_timeout(Some(STALL))?;
    let mut received = offset;
    let mut frames = 0u32;
    let res = (|| -> Result<()> {
        loop {
            match ch.recv_frame()? {
                (KIND_DATA, b) => {
                    f.write_all(&b)?;
                    received += b.len() as u64;
                    rx.event(RecvEvent::Progress {
                        id: id.clone(),
                        received,
                    });
                    frames += 1;
                    if frames.is_multiple_of(32) && !meta_path(&id).exists() {
                        bail!("cancelled on this Mac");
                    }
                }
                (KIND_END, _) => return Ok(()),
                _ => bail!("unexpected message during transfer"),
            }
        }
    })();
    if let Err(e) = res {
        let _ = f.sync_all();
        rx.event(RecvEvent::Interrupted {
            id: id.clone(),
            error: friendly(&e),
        });
        return Err(e);
    }
    f.sync_all()?;
    drop(f);
    rx.event(RecvEvent::Verifying { id: id.clone() });
    let ok =
        std::fs::metadata(&part)?.len() == pending.size && sha256_file(&part)? == pending.sha256;
    if !ok {
        let _ = std::fs::remove_file(&part);
        ch.send_msg(&Msg::Corrupt)?;
        rx.event(RecvEvent::Corrupt { id });
        return Ok(());
    }
    std::fs::rename(&part, package_path(&id))?;
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
        let mut out = pack("laptop".into(), manifest(), &on).unwrap();
        // Replace the tiny package with 3 MB of noise so the cut lands mid-stream.
        let mut noise = vec![0u8; 3 << 20];
        getrandom::getrandom(&mut noise).unwrap();
        std::fs::write(&out.path, &noise).unwrap();
        out.size = noise.len() as u64;
        out.sha256 = sha256_file(&out.path).unwrap();

        let proxy = flaky_proxy(direct, 1 << 20);
        let (cancel, now) = (AtomicBool::new(false), AtomicBool::new(true));
        assert!(send(proxy, &mut out, &cancel, &now, &on).unwrap());

        let log = log.into_inner().unwrap();
        assert_eq!(codes.lock().unwrap().len(), 1, "a resume needs no new code");
        assert!(log.iter().any(|e| matches!(e, SendEvent::Retrying { .. })));
        assert!(
            log.iter()
                .any(|e| matches!(e, SendEvent::Sending { resumed: true, .. }))
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
