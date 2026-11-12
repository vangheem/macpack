//! Finding other Macs running macpack on the local network, over mDNS (Bonjour).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const SERVICE: &str = "_macpack._tcp.local.";

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    /// The peer's device id (its mDNS instance name).
    pub id: String,
    pub name: String,
    pub addr: SocketAddr,
}

/// Advertises this Mac and reports the peer list whenever it changes. Keep the returned
/// daemon alive for as long as discovery should run.
pub fn start(
    device_id: &str,
    name: &str,
    port: u16,
    on_change: impl Fn(Vec<Peer>) + Send + 'static,
) -> Result<ServiceDaemon> {
    let mdns = ServiceDaemon::new().context("start mDNS")?;
    let host = format!("{device_id}.local.");
    let props = [("name", name), ("v", env!("CARGO_PKG_VERSION"))];
    let info = ServiceInfo::new(SERVICE, device_id, &host, "", port, &props[..])
        .context("describe service")?
        .enable_addr_auto();
    mdns.register(info).context("advertise")?;
    let events = mdns.browse(SERVICE).context("browse")?;
    let me = device_id.to_string();
    std::thread::spawn(move || {
        let mut peers: BTreeMap<String, Peer> = BTreeMap::new();
        while let Ok(ev) = events.recv() {
            let changed = match ev {
                ServiceEvent::ServiceResolved(info) => {
                    let id = instance(info.get_fullname());
                    // Prefer LAN addresses over VPN ones (Tailscale and friends use 100.64/10).
                    let addr = info
                        .get_addresses_v4()
                        .into_iter()
                        .filter(|a| !a.is_loopback())
                        .min_by_key(|a| !a.is_private())
                        .map(|a| IpAddr::V4(*a));
                    match addr {
                        Some(ip) if id != me => {
                            let peer = Peer {
                                name: info.get_property_val_str("name").unwrap_or(&id).to_string(),
                                id: id.clone(),
                                addr: SocketAddr::new(ip, info.get_port()),
                            };
                            peers.insert(id, peer.clone()) != Some(peer)
                        }
                        _ => false,
                    }
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    peers.remove(&instance(&fullname)).is_some()
                }
                _ => false,
            };
            if changed {
                on_change(peers.values().cloned().collect());
            }
        }
    });
    Ok(mdns)
}

/// `abc123._macpack._tcp.local.` → `abc123`.
fn instance(fullname: &str) -> String {
    fullname
        .strip_suffix(SERVICE)
        .unwrap_or(fullname)
        .trim_end_matches('.')
        .to_string()
}

/// This Mac's name as people know it ("Jane's MacBook Pro").
pub fn computer_name() -> String {
    std::process::Command::new("/usr/sbin/scutil")
        .args(["--get", "ComputerName"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "This Mac".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn instance_names() {
        assert_eq!(super::instance("ab12._macpack._tcp.local."), "ab12");
    }

    /// Uses the real network: `cargo test -- --ignored`. Two advertisers find each other.
    #[test]
    #[ignore]
    fn two_macs_find_each_other() {
        let (tx, rx) = std::sync::mpsc::channel();
        let _a = super::start("test-a", "A", 40001, |_| {}).unwrap();
        let _b = super::start("test-b", "B", 40002, move |peers| {
            let _ = tx.send(peers);
        })
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Ok(peers) = rx.recv_timeout(std::time::Duration::from_secs(1))
                && let Some(p) = peers.iter().find(|p| p.id == "test-a")
            {
                assert_eq!(p.name, "A");
                assert_eq!(p.addr.port(), 40001);
                return;
            }
        }
        panic!("B never saw A");
    }
}
