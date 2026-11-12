//! The encrypted transfer between two Macs on the local network.
//!
//! Handshake (initiator = sender, responder = receiver), over plain TCP:
//!
//! 1. I → R: `MACPACK1` and SHA-256 of I's ephemeral X25519 public key (a commitment).
//! 2. R → I: `MACPACK1` and R's ephemeral public key.
//! 3. I → R: I's public key; R checks it against the commitment.
//!
//! Both sides derive two ChaCha20-Poly1305 keys (one per direction) from the X25519 shared
//! secret with HKDF over the transcript, and a 6-digit code from the same transcript. Each Mac
//! shows the code; the receiver accepts only when they match. Someone in the middle would hold
//! different keys with each side, so the codes would differ, and the commitment stops them
//! from searching for keys that make the codes collide.
//!
//! After the handshake every message is a frame: a big-endian `u32` length, then ciphertext
//! whose first plaintext byte says what it is (JSON control message, file data, or end).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::package::{self, Manifest};

const MAGIC: &[u8; 8] = b"MACPACK1";
const MAX_FRAME: usize = 4 << 20;
const CHUNK: usize = 256 << 10;
/// How long the sender waits for the person at the other Mac to accept.
const DECISION_TIMEOUT: Duration = Duration::from_secs(600);

const KIND_JSON: u8 = 0;
const KIND_DATA: u8 = 1;
const KIND_END: u8 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Msg {
    Offer { from: String, manifest: Manifest },
    Accept,
    Decline,
    Received,
}

pub struct Channel {
    stream: TcpStream,
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_n: u64,
    recv_n: u64,
    /// The 6-digit verification code both sides show.
    pub code: String,
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

/// Keys and code from the shared secret and both public keys.
fn derive(shared: &[u8; 32], i_pub: &[u8; 32], r_pub: &[u8; 32]) -> ([u8; 32], [u8; 32], String) {
    let mut t = Sha256::new();
    t.update(MAGIC);
    t.update(i_pub);
    t.update(r_pub);
    let transcript = t.finalize();
    let hk = Hkdf::<Sha256>::new(Some(&transcript), shared);
    let (mut i2r, mut r2i, mut sas) = ([0u8; 32], [0u8; 32], [0u8; 4]);
    hk.expand(b"macpack i2r", &mut i2r).expect("hkdf");
    hk.expand(b"macpack r2i", &mut r2i).expect("hkdf");
    hk.expand(b"macpack code", &mut sas).expect("hkdf");
    let n = u32::from_be_bytes(sas) % 1_000_000;
    (i2r, r2i, format!("{:03} {:03}", n / 1000, n % 1000))
}

fn read_exact<const N: usize>(s: &mut TcpStream) -> Result<[u8; N]> {
    let mut b = [0u8; N];
    s.read_exact(&mut b)?;
    Ok(b)
}

impl Channel {
    pub fn initiate(mut stream: TcpStream) -> Result<Channel> {
        let secret = StaticSecret::from(random32());
        let mine = PublicKey::from(&secret).to_bytes();
        stream.write_all(MAGIC)?;
        stream.write_all(&Sha256::digest(mine))?;
        if &read_exact::<8>(&mut stream)? != MAGIC {
            bail!("the other side isn't macpack");
        }
        let theirs = read_exact::<32>(&mut stream)?;
        stream.write_all(&mine)?;
        let shared = secret.diffie_hellman(&PublicKey::from(theirs)).to_bytes();
        let (i2r, r2i, code) = derive(&shared, &mine, &theirs);
        Ok(Channel::new(stream, i2r, r2i, code))
    }

    pub fn respond(mut stream: TcpStream) -> Result<Channel> {
        if &read_exact::<8>(&mut stream)? != MAGIC {
            bail!("not a macpack connection");
        }
        let commitment = read_exact::<32>(&mut stream)?;
        let secret = StaticSecret::from(random32());
        let mine = PublicKey::from(&secret).to_bytes();
        stream.write_all(MAGIC)?;
        stream.write_all(&mine)?;
        let theirs = read_exact::<32>(&mut stream)?;
        if Sha256::digest(theirs).as_slice() != commitment {
            bail!("handshake commitment didn't match");
        }
        let shared = secret.diffie_hellman(&PublicKey::from(theirs)).to_bytes();
        let (i2r, r2i, code) = derive(&shared, &theirs, &mine);
        Ok(Channel::new(stream, r2i, i2r, code))
    }

    fn new(stream: TcpStream, send: [u8; 32], recv: [u8; 32], code: String) -> Channel {
        Channel {
            stream,
            send: ChaCha20Poly1305::new(Key::from_slice(&send)),
            recv: ChaCha20Poly1305::new(Key::from_slice(&recv)),
            send_n: 0,
            recv_n: 0,
            code,
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

/// Buffers writes into encrypted data frames.
struct FrameWriter<'a> {
    ch: &'a mut Channel,
    buf: Vec<u8>,
}

impl Write for FrameWriter<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= CHUNK {
            self.flush()?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let b = std::mem::take(&mut self.buf);
            self.ch
                .send_frame(KIND_DATA, &b)
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    }
}

/// What the sender sees while a transfer runs.
pub enum SendEvent {
    /// Connected; show this code and wait for the other Mac.
    Code(String),
    Accepted,
    /// Compressed bytes sent so far.
    Progress(u64),
}

/// Sends `manifest` and its files to the Mac at `addr`. Returns `Ok(false)` if they declined.
pub fn send(
    addr: SocketAddr,
    from: String,
    manifest: Manifest,
    on: impl Fn(SendEvent),
) -> Result<bool> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .with_context(|| format!("connect to {addr}"))?;
    stream.set_nodelay(true)?;
    let mut ch = Channel::initiate(stream)?;
    on(SendEvent::Code(ch.code.clone()));
    let items = manifest.items.clone();
    ch.send_msg(&Msg::Offer { from, manifest })?;
    ch.stream.set_read_timeout(Some(DECISION_TIMEOUT))?;
    match ch.recv_msg()? {
        Msg::Accept => {}
        Msg::Decline => return Ok(false),
        m => bail!("unexpected reply {m:?}"),
    }
    on(SendEvent::Accepted);
    {
        let mut w = FrameWriter {
            ch: &mut ch,
            buf: Vec::new(),
        };
        package::write_files(&items, &mut w, |n| on(SendEvent::Progress(n)))?;
        w.flush()?;
    }
    ch.send_frame(KIND_END, &[])?;
    match ch.recv_msg()? {
        Msg::Received => Ok(true),
        m => bail!("unexpected reply {m:?}"),
    }
}

/// An incoming offer, waiting for the user.
pub struct Offer {
    pub from: String,
    pub code: String,
    pub manifest: Manifest,
}

/// A package saved in the inbox.
#[derive(Debug, Clone)]
pub struct Saved {
    pub id: String,
    pub manifest: Manifest,
}

pub fn inbox() -> PathBuf {
    crate::store::data_dir().join("inbox")
}

pub fn package_path(id: &str) -> PathBuf {
    inbox().join(format!("{id}.tar.gz"))
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
            if !package_path(&id).exists() {
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

/// Callbacks a receiving Mac uses to involve the user.
pub trait Receiver: Send + Sync + 'static {
    /// Blocks until the user accepts or declines.
    fn decide(&self, offer: Offer) -> bool;
    fn progress(&self, bytes: u64);
    fn done(&self, result: Result<Saved>);
}

/// Listens on a free port in the background, returning it.
pub fn listen(rx: std::sync::Arc<dyn Receiver>) -> Result<u16> {
    let listener = TcpListener::bind(("0.0.0.0", 0)).context("listen")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let rx = rx.clone();
            std::thread::spawn(move || {
                if let Err(e) = receive(stream, &*rx) {
                    rx.done(Err(e));
                }
            });
        }
    });
    Ok(port)
}

fn receive(stream: TcpStream, rx: &dyn Receiver) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut ch = Channel::respond(stream)?;
    let Msg::Offer { from, manifest } = ch.recv_msg()? else {
        bail!("expected an offer");
    };
    if manifest.format > package::FORMAT {
        ch.send_msg(&Msg::Decline)?;
        bail!("{from} runs a newer macpack; update this one first");
    }
    let code = ch.code.clone();
    let accepted = rx.decide(Offer {
        from,
        code,
        manifest: manifest.clone(),
    });
    if !accepted {
        ch.send_msg(&Msg::Decline)?;
        return Ok(());
    }
    ch.send_msg(&Msg::Accept)?;
    ch.stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    let saved = save_stream(&mut ch, manifest, |n| rx.progress(n))?;
    ch.send_msg(&Msg::Received)?;
    rx.done(Ok(saved));
    Ok(())
}

fn save_stream(ch: &mut Channel, manifest: Manifest, progress: impl Fn(u64)) -> Result<Saved> {
    let dir = inbox();
    std::fs::create_dir_all(&dir)?;
    let id = format!("{}-{}", manifest.created, package::now());
    let part = dir.join(format!("{id}.part"));
    let result = (|| -> Result<()> {
        let mut f = std::fs::File::create(&part)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let mut total = 0u64;
        loop {
            match ch.recv_frame()? {
                (KIND_DATA, b) => {
                    f.write_all(&b)?;
                    total += b.len() as u64;
                    progress(total);
                }
                (KIND_END, _) => break,
                _ => bail!("unexpected message during transfer"),
            }
        }
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, package_path(&id))?;
    write_private(
        &dir.join(format!("{id}.json")),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(Saved { id, manifest })
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

    type Done = mpsc::Sender<(String, Result<Saved>)>;

    struct Auto(Mutex<Option<Done>>, Mutex<String>);

    impl Receiver for Auto {
        fn decide(&self, offer: Offer) -> bool {
            *self.1.lock().unwrap() = offer.code;
            offer.from == "laptop"
        }
        fn progress(&self, _: u64) {}
        fn done(&self, r: Result<Saved>) {
            let code = self.1.lock().unwrap().clone();
            if let Some(tx) = self.0.lock().unwrap().as_ref() {
                let _ = tx.send((code, r));
            }
        }
    }

    /// Sends a real package (a Brewfile-only one, so it doesn't read $HOME) between two
    /// endpoints on localhost: both sides see the same code and the receiver saves it.
    #[test]
    fn sends_a_package_over_an_encrypted_channel() {
        let tmp = std::env::temp_dir().join(format!("macpack-net-{}", std::process::id()));
        // SAFETY: tests in this module are the only ones touching XDG_DATA_HOME.
        unsafe { std::env::set_var("XDG_DATA_HOME", &tmp) };
        let (tx, rx) = mpsc::channel();
        let port = listen(std::sync::Arc::new(Auto(
            Mutex::new(Some(tx)),
            Mutex::new(String::new()),
        )))
        .unwrap();
        let manifest = Manifest::new(
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
        );
        let sender_code = Mutex::new(String::new());
        let ok = send(
            ([127, 0, 0, 1], port).into(),
            "laptop".into(),
            manifest.clone(),
            |e| {
                if let SendEvent::Code(c) = e {
                    *sender_code.lock().unwrap() = c;
                }
            },
        )
        .unwrap();
        assert!(ok);
        let (code, saved) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let saved = saved.unwrap();
        assert_eq!(code, *sender_code.lock().unwrap());
        assert_eq!(code.len(), 7);
        assert_eq!(saved.manifest, manifest);
        assert!(package_path(&saved.id).exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
