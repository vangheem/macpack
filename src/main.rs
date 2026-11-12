//! macpack: what this Mac has (apps, tools, settings, folders) on one side, other Macs on the
//! network and packages received from them on the other. Send a package from the old Mac,
//! accept it on the new one, review it, and apply it.

mod appbundle;
mod discovery;
mod inventory;
mod net;
mod package;
mod store;
mod update;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use rune::{
    AppSpec, Chrome, Cx, El, KeyEvent, ScrollSpec, TextEdit, Tx, Waker, col, el, row, text,
};
use rune_kit::shell::{
    self, PaneState, Sidebar, SidebarRow, SidebarSection, SidebarToggle, SplitView, Toolbar,
};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, Checkbox, ControlSize, Dialog, Kit, Spinner,
    TextInput,
};

use discovery::Peer;
use inventory::{Inventory, Item, Kind, human_size};
use net::Saved;
use package::{Log, Manifest};
use store::Store;

type Job = Box<dyn FnOnce(&mut App, &mut Tx) + Send>;

#[derive(Clone, PartialEq)]
enum Page {
    Inventory,
    Peer(String),
    Received(String),
}

/// Which item list a checkbox belongs to.
#[derive(Clone, Copy, PartialEq)]
enum List {
    Inventory,
    Received,
}

enum Confirm {
    InstallApp,
    Update,
    Apply,
    Delete(String),
    DeleteSet(String),
}

struct Sending {
    peer: String,
    code: Option<String>,
    accepted: bool,
    bytes: Arc<AtomicU64>,
    /// Ok(true) sent, Ok(false) declined.
    result: Option<Result<bool, String>>,
}

struct Incoming {
    from: String,
    code: String,
    manifest: Manifest,
    reply: Sender<bool>,
}

struct App {
    store: Store,
    jobs: (Sender<Job>, Receiver<Job>),
    waker: Option<Waker>,
    name: String,
    sidebar: PaneState,
    page: Page,
    inventory: Option<Inventory>,
    scanning: bool,
    collapsed: HashSet<(bool, Kind)>,
    /// Found on the network and added by hand, merged.
    peers: Vec<Peer>,
    found: Vec<Peer>,
    /// Macs that answered on macpack's port when the local subnet was swept.
    swept: Vec<Peer>,
    /// Manual peer id → its name and version once it answered, or why it didn't.
    reach: HashMap<String, Result<(String, String), String>>,
    /// The port this Mac listens on.
    port: Option<u16>,
    connect: Option<TextEdit>,
    /// This Mac's LAN addresses, shown so they can be typed on the other Mac.
    my_ips: Vec<std::net::Ipv4Addr>,
    net_error: Option<String>,
    _mdns: Option<mdns_sd::ServiceDaemon>,
    sending: Option<Sending>,
    incoming: Option<Incoming>,
    /// Who is sending, and bytes received so far.
    receiving: Option<(String, Arc<AtomicU64>)>,
    received_bytes: Arc<AtomicU64>,
    saved: Vec<Saved>,
    /// Item keys to apply from the open received package.
    apply_keys: HashSet<String>,
    applying: bool,
    apply_log: Vec<Log>,
    applied_ok: Option<bool>,
    add_folder: Option<TextEdit>,
    /// The "Save selection as" dialog's name field.
    save_set: Option<TextEdit>,
    /// The running scan's steps: name, what it's looking at or found, finished.
    scan_steps: Vec<(&'static str, String, bool)>,
    confirm: Option<Confirm>,
    toast: Option<(String, bool)>,
    toast_until: Option<f64>,
    update: Option<String>,
    update_hidden: bool,
    updating: bool,
    next_update_check: f64,
}

fn init() -> App {
    App {
        store: Store::load(),
        jobs: channel(),
        waker: None,
        name: discovery::computer_name(),
        sidebar: PaneState::new(280.0).range(200.0, 440.0),
        page: Page::Inventory,
        inventory: Inventory::load_cached(),
        scanning: false,
        collapsed: [Kind::Formula, Kind::Tap, Kind::Defaults]
            .into_iter()
            .map(|k| (false, k))
            .collect(),
        peers: Vec::new(),
        found: Vec::new(),
        swept: Vec::new(),
        reach: HashMap::new(),
        port: None,
        connect: None,
        my_ips: Vec::new(),
        net_error: None,
        _mdns: None,
        sending: None,
        incoming: None,
        receiving: None,
        received_bytes: Arc::new(AtomicU64::new(0)),
        saved: Vec::new(),
        apply_keys: HashSet::new(),
        applying: false,
        apply_log: Vec::new(),
        applied_ok: None,
        add_folder: None,
        save_set: None,
        scan_steps: Vec::new(),
        confirm: None,
        toast: None,
        toast_until: None,
        update: None,
        update_hidden: false,
        updating: false,
        next_update_check: 0.0,
    }
}

/// Bridges the network listener to the UI: offers become a dialog, results become jobs.
struct UiReceiver {
    name: String,
    jobs: Sender<Job>,
    waker: Option<Waker>,
    bytes: Arc<AtomicU64>,
}

impl UiReceiver {
    fn post(&self, job: Job) {
        let _ = self.jobs.send(job);
        if let Some(w) = &self.waker {
            w();
        }
    }
}

impl net::Receiver for UiReceiver {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn decide(&self, offer: net::Offer) -> bool {
        let (reply, answer) = channel();
        self.post(Box::new(move |s: &mut App, _| {
            if s.incoming.is_some() || s.receiving.is_some() {
                let _ = reply.send(false);
                return;
            }
            s.incoming = Some(Incoming {
                from: offer.from,
                code: offer.code,
                manifest: offer.manifest,
                reply,
            });
        }));
        answer
            .recv_timeout(Duration::from_secs(600))
            .unwrap_or(false)
    }

    fn progress(&self, bytes: u64) {
        self.bytes.store(bytes, Ordering::Relaxed);
    }

    fn done(&self, result: anyhow::Result<Saved>) {
        self.post(Box::new(move |s: &mut App, _| {
            s.receiving = None;
            match result {
                Ok(saved) => {
                    s.notify(
                        format!("Received a package from {}", saved.manifest.from),
                        false,
                    );
                    let id = saved.id.clone();
                    s.saved.insert(0, saved);
                    s.open_received(&id);
                }
                Err(e) => s.notify(format!("Receiving failed: {e:#}"), true),
            }
        }));
    }
}

impl App {
    fn bg<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
        done: impl FnOnce(&mut App, T, &mut Tx) + Send + 'static,
    ) {
        let (sender, waker) = (self.jobs.0.clone(), self.waker.clone());
        std::thread::spawn(move || {
            let out = work();
            let _ = sender.send(Box::new(move |s: &mut App, tx: &mut Tx| done(s, out, tx)));
            if let Some(w) = waker {
                w();
            }
        });
    }

    /// Sends a job to the UI thread from any thread.
    fn poster(&self) -> impl Fn(Job) + Send + Clone + 'static {
        let (sender, waker) = (self.jobs.0.clone(), self.waker.clone());
        move |job| {
            let _ = sender.send(job);
            if let Some(w) = &waker {
                w();
            }
        }
    }

    fn notify(&mut self, msg: impl Into<String>, error: bool) {
        self.toast = Some((msg.into(), error));
        self.toast_until = None;
    }

    fn save(&mut self) {
        if let Err(e) = self.store.save() {
            self.notify(format!("Couldn't save state: {e}"), true);
        }
    }

    fn scan(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.scan_steps.clear();
        let folders = self.store.folders.clone();
        let post = self.poster();
        self.bg(
            move || {
                let on = move |p: inventory::Progress| {
                    post(Box::new(move |s: &mut App, _| s.scan_progress(p)));
                };
                let inv = inventory::scan(&folders, &on);
                inv.save_cached();
                inv
            },
            |s, inv, _| {
                s.scanning = false;
                s.inventory = Some(inv);
            },
        );
    }

    fn scan_progress(&mut self, p: inventory::Progress) {
        use inventory::Progress::*;
        let (name, detail, done) = match p {
            Start(n) => (n, String::new(), false),
            Detail(n, d) => (n, d, false),
            Done(n, d) => (n, d, true),
        };
        match self.scan_steps.iter_mut().find(|st| st.0 == name) {
            // A late Detail from a parallel worker mustn't reopen a finished step.
            Some(st) if !st.2 => *st = (name, detail, done),
            Some(_) => {}
            None => self.scan_steps.push((name, detail, done)),
        }
    }

    fn save_set(&mut self) {
        let Some(edit) = &self.save_set else { return };
        let name = edit.text.trim().to_string();
        if name.is_empty() {
            return;
        }
        self.save_set = None;
        self.store.save_set(&name);
        self.save();
        self.notify(format!("Saved as \u{201c}{name}\u{201d}"), false);
    }

    fn load_set(&mut self, name: &str) {
        if !self.store.load_set(name) {
            return;
        }
        self.save();
        self.page = Page::Inventory;
        self.sync_folders();
    }

    fn delete_set(&mut self, name: &str) {
        self.confirm = None;
        self.store.delete_set(name);
        self.save();
    }

    /// Makes the inventory's folder items match the selection's folders, measuring new ones.
    fn sync_folders(&mut self) {
        let wanted = self.store.folders.clone();
        let Some(inv) = &mut self.inventory else {
            return;
        };
        inv.items
            .retain(|i| i.kind != Kind::Folder || wanted.contains(&i.id));
        let have: HashSet<String> = inv
            .items
            .iter()
            .filter(|i| i.kind == Kind::Folder)
            .map(|i| i.id.clone())
            .collect();
        for rel in wanted.into_iter().filter(|r| !have.contains(r)) {
            self.bg(
                move || inventory::folder_item(&rel),
                |s, item, _| {
                    if let Some(inv) = &mut s.inventory {
                        inv.items.retain(|i| i.key() != item.key());
                        let at = inv
                            .items
                            .iter()
                            .position(|i| i.kind == Kind::Defaults)
                            .unwrap_or(inv.items.len());
                        inv.items.insert(at, item);
                    }
                },
            );
        }
    }

    fn start_network(&mut self) {
        let rx = Arc::new(UiReceiver {
            name: self.name.clone(),
            jobs: self.jobs.0.clone(),
            waker: self.waker.clone(),
            bytes: self.received_bytes.clone(),
        });
        let port = match net::listen(rx) {
            Ok(p) => p,
            Err(e) => {
                self.net_error = Some(format!("Can't receive: {e:#}"));
                return;
            }
        };
        self.port = Some(port);
        self.my_ips = net::local_ips();
        // mDNS is often blocked (Local Network privacy, Wi-Fi client isolation of multicast),
        // while plain TCP still works, so also sweep the subnet for macpack's port.
        let (post, mine) = (self.poster(), self.my_ips.clone());
        std::thread::spawn(move || {
            loop {
                let peers = net::sweep(&mine);
                post(Box::new(move |s: &mut App, _| {
                    s.swept = peers;
                    s.merge_peers();
                }));
                std::thread::sleep(Duration::from_secs(30));
            }
        });
        for a in self.store.manual_peers.clone() {
            if let Some(addr) = net::parse_addr(&a) {
                self.check_peer(addr);
            }
        }
        let post = self.poster();
        match discovery::start(&self.store.device_id, &self.name, port, move |peers| {
            post(Box::new(move |s: &mut App, _| {
                s.found = peers;
                s.merge_peers();
            }));
        }) {
            Ok(d) => self._mdns = Some(d),
            Err(e) => self.net_error = Some(format!("Can't look for other Macs: {e:#}")),
        }
    }

    /// Discovered Macs, then ones added by hand that discovery didn't also find.
    fn merge_peers(&mut self) {
        let mut all = self.found.clone();
        for p in &self.swept {
            if !all.iter().any(|q| q.addr.ip() == p.addr.ip()) {
                all.push(p.clone());
            }
        }
        for a in &self.store.manual_peers {
            let Some(addr) = net::parse_addr(a) else {
                continue;
            };
            if all.iter().any(|p| p.addr == addr) {
                continue;
            }
            let id = manual_id(&addr);
            let name = match self.reach.get(&id) {
                Some(Ok((name, _))) => name.clone(),
                _ => addr.to_string(),
            };
            all.push(Peer { id, name, addr });
        }
        self.peers = all;
    }

    /// Pings a hand-added Mac to learn its name, or why it can't be reached.
    fn check_peer(&mut self, addr: std::net::SocketAddr) {
        let id = manual_id(&addr);
        self.reach.remove(&id);
        self.merge_peers();
        self.bg(
            move || net::ping(addr).map_err(|e| format!("{e:#}")),
            move |s, res, _| {
                s.reach.insert(id, res);
                s.merge_peers();
            },
        );
    }

    fn connect(&mut self) {
        let Some(edit) = &self.connect else { return };
        let Some(addr) = net::parse_addr(&edit.text) else {
            self.notify("Enter an address like 192.168.1.20", true);
            return;
        };
        self.connect = None;
        let key = addr.to_string();
        if !self.store.manual_peers.contains(&key) {
            self.store.manual_peers.push(key);
            self.save();
        }
        self.check_peer(addr);
        self.page = Page::Peer(manual_id(&addr));
    }

    fn forget_peer(&mut self, addr: std::net::SocketAddr) {
        self.store
            .manual_peers
            .retain(|a| net::parse_addr(a) != Some(addr));
        self.save();
        self.reach.remove(&manual_id(&addr));
        self.merge_peers();
        if self.page == Page::Peer(manual_id(&addr)) {
            self.page = Page::Inventory;
        }
    }

    fn is_on(&self, list: List, it: &Item) -> bool {
        match list {
            List::Inventory => *self.store.choices.get(&it.key()).unwrap_or(&it.default_on),
            List::Received => self.apply_keys.contains(&it.key()),
        }
    }

    fn set_on(&mut self, list: List, keys: Vec<(String, bool)>, on: bool) {
        match list {
            List::Inventory => {
                for (k, default) in keys {
                    if on == default {
                        self.store.choices.remove(&k);
                    } else {
                        self.store.choices.insert(k, on);
                    }
                }
                self.save();
            }
            List::Received => {
                for (k, _) in keys {
                    if on {
                        self.apply_keys.insert(k);
                    } else {
                        self.apply_keys.remove(&k);
                    }
                }
            }
        }
    }

    /// The selected inventory items: what a package from this Mac contains.
    fn selection(&self) -> Vec<Item> {
        self.inventory
            .iter()
            .flat_map(|i| &i.items)
            .filter(|i| self.is_on(List::Inventory, i))
            .cloned()
            .collect()
    }

    fn add_folder(&mut self) {
        let Some(edit) = &self.add_folder else { return };
        let Some(rel) = inventory::home_relative(&edit.text) else {
            self.notify(
                "Pick a folder inside your home folder, like ~/projects",
                true,
            );
            return;
        };
        if !inventory::home().join(&rel).is_dir() {
            self.notify(format!("~/{rel} isn't a folder"), true);
            return;
        }
        self.add_folder = None;
        self.store.folders.insert(rel.clone());
        self.save();
        self.bg(
            move || inventory::folder_item(&rel),
            |s, item, _| {
                if let Some(inv) = &mut s.inventory {
                    inv.items.retain(|i| i.key() != item.key());
                    inv.items.push(item);
                }
            },
        );
    }

    fn remove_folder(&mut self, rel: &str) {
        self.store.folders.remove(rel);
        self.store
            .choices
            .remove(&format!("{:?}:{rel}", Kind::Folder));
        self.save();
        if let Some(inv) = &mut self.inventory {
            inv.items
                .retain(|i| !(i.kind == Kind::Folder && i.id == rel));
        }
    }

    fn send_to(&mut self, peer: &Peer) {
        if self.sending.as_ref().is_some_and(|t| t.result.is_none()) {
            return;
        }
        let items = self.selection();
        if items.is_empty() {
            self.notify("Nothing is selected to send", true);
            return;
        }
        let bytes = Arc::new(AtomicU64::new(0));
        self.sending = Some(Sending {
            peer: peer.id.clone(),
            code: None,
            accepted: false,
            bytes: bytes.clone(),
            result: None,
        });
        let (addr, from) = (peer.addr, self.name.clone());
        let manifest = Manifest::new(from.clone(), items);
        let post = self.poster();
        self.bg(
            move || {
                net::send(addr, from, manifest, |ev| match ev {
                    net::SendEvent::Code(code) => post(Box::new(move |s: &mut App, _| {
                        if let Some(t) = &mut s.sending {
                            t.code = Some(code);
                        }
                    })),
                    net::SendEvent::Accepted => post(Box::new(|s: &mut App, _| {
                        if let Some(t) = &mut s.sending {
                            t.accepted = true;
                        }
                    })),
                    net::SendEvent::Progress(n) => bytes.store(n, Ordering::Relaxed),
                })
            },
            |s, res, _| {
                if let Some(t) = &mut s.sending {
                    t.result = Some(res.map_err(|e| format!("{e:#}")));
                }
            },
        );
    }

    fn answer(&mut self, accept: bool) {
        let Some(inc) = self.incoming.take() else {
            return;
        };
        if accept {
            self.received_bytes.store(0, Ordering::Relaxed);
            self.receiving = Some((inc.from.clone(), self.received_bytes.clone()));
        }
        let _ = inc.reply.send(accept);
    }

    fn open_received(&mut self, id: &str) {
        let Some(saved) = self.saved.iter().find(|p| p.id == id) else {
            return;
        };
        if self.page != Page::Received(id.to_string()) {
            self.apply_keys = saved.manifest.items.iter().map(Item::key).collect();
            self.apply_log.clear();
            self.applied_ok = None;
        }
        self.page = Page::Received(id.to_string());
    }

    fn apply(&mut self) {
        self.confirm = None;
        let Page::Received(id) = &self.page else {
            return;
        };
        let Some(saved) = self.saved.iter().find(|p| &p.id == id).cloned() else {
            return;
        };
        self.applying = true;
        self.applied_ok = None;
        self.apply_log.clear();
        let keys = self.apply_keys.clone();
        let path = net::package_path(&saved.id);
        let post = self.poster();
        self.bg(
            move || {
                package::apply(&path, &saved.manifest, &keys, &|line| {
                    post(Box::new(move |s: &mut App, _| s.apply_log.push(line)));
                })
            },
            |s, ok, _| {
                s.applying = false;
                s.applied_ok = Some(ok);
                s.notify(
                    if ok {
                        "Package applied"
                    } else {
                        "Applied, with some steps failing; see the log"
                    },
                    !ok,
                );
            },
        );
    }

    fn delete_received(&mut self, id: &str) {
        self.confirm = None;
        net::delete_saved(id);
        self.saved.retain(|p| p.id != id);
        if self.page == Page::Received(id.to_string()) {
            self.page = Page::Inventory;
        }
    }

    fn check_for_update(&mut self) {
        self.bg(update::latest_release, |s, res, _| {
            let Ok(tag) = res else { return };
            let newer = update::is_newer(&tag, update::current());
            let skipped = s.store.skipped_version.as_deref() == Some(tag.as_str());
            s.update = (newer && !skipped).then_some(tag);
        });
    }

    fn run_update(&mut self) {
        let Some(prefix) = update::brew_prefix() else {
            return;
        };
        self.updating = true;
        self.bg(
            move || update::brew_upgrade(&prefix).and_then(|_| update::relaunch()),
            |s, res, tx| {
                s.updating = false;
                match res {
                    Ok(()) => tx.quit(),
                    Err(e) => {
                        s.confirm = None;
                        s.notify(format!("Update failed: {e:#}"), true);
                    }
                }
            },
        );
    }

    fn install_app(&mut self) {
        self.confirm = None;
        self.bg(appbundle::install, |s, res, _| match res {
            Ok(app) => s.notify(
                format!(
                    "Added {}. Open macpack from Spotlight or Launchpad.",
                    app.display()
                ),
                false,
            ),
            Err(e) => s.notify(format!("Couldn't add macpack.app: {e:#}"), true),
        });
    }
}

fn setup(s: &mut App, waker: Waker) {
    s.waker = Some(waker);
    if rune::tooling::headless_run().is_some() {
        return;
    }
    if appbundle::supported()
        && !appbundle::launched_from_app()
        && !appbundle::installed()
        && !s.store.skip_app_prompt
    {
        s.confirm = Some(Confirm::InstallApp);
    }
    s.saved = net::saved();
    s.start_network();
    s.scan();
}

fn poll(s: &mut App, now: f64, tx: &mut Tx) -> bool {
    let mut changed = false;
    while let Ok(job) = s.jobs.1.try_recv() {
        job(s, tx);
        changed = true;
    }
    // Redraw progress while bytes move.
    let moving = s.receiving.is_some()
        || s.sending
            .as_ref()
            .is_some_and(|t| t.accepted && t.result.is_none());
    if moving {
        tx.wake_after(Duration::from_millis(250));
        changed = true;
    }
    if now >= s.next_update_check && rune::tooling::headless_run().is_none() {
        s.next_update_check = now + update::CHECK_EVERY_SECS;
        tx.wake_after(Duration::from_secs_f64(update::CHECK_EVERY_SECS));
        s.check_for_update();
    }
    if s.toast.is_some() {
        match s.toast_until {
            None => {
                let secs = if s.toast.as_ref().is_some_and(|t| t.1) {
                    8.0
                } else {
                    4.0
                };
                s.toast_until = Some(now + secs);
                tx.wake_after(Duration::from_secs_f64(secs));
            }
            Some(t) if now >= t => {
                s.toast = None;
                s.toast_until = None;
                changed = true;
            }
            _ => {}
        }
    }
    changed
}

fn on_key(s: &mut App, ev: &KeyEvent, _tx: &mut Tx) -> bool {
    if shell::is_sidebar_toggle(ev) {
        s.sidebar.toggle();
        return true;
    }
    if ev.is_command('r') {
        s.scan();
        return true;
    }
    false
}

// ---------------------------------------------------------------------------------------- view

fn view(s: &App, cx: &mut Cx<App>) -> El {
    let k = rune_theme_opencode::kit(cx.system_dark()).clone();
    let mut layer = Vec::new();
    let title = match &s.page {
        Page::Inventory => s.name.clone(),
        Page::Peer(id) => s
            .peers
            .iter()
            .find(|p| &p.id == id)
            .map(|p| format!("Send to {}", p.name))
            .unwrap_or_else(|| "Send".into()),
        Page::Received(id) => s
            .saved
            .iter()
            .find(|p| &p.id == id)
            .map(|p| format!("From {}", p.manifest.from))
            .unwrap_or_else(|| "Received".into()),
    };
    let mut actions = row().gap(6.0).items_center();
    if s.scanning {
        actions = actions.child(Spinner::new().build(&k));
    }
    if s.page == Page::Inventory {
        actions = actions
            .child(
                Button::new("Add folder…")
                    .variant(ButtonVariant::Ghost)
                    .control_size(ControlSize::Small)
                    .on_press(|s: &mut App| s.add_folder = Some(TextEdit::new("~/")))
                    .build(&k),
            )
            .child(
                Button::new("Rescan")
                    .variant(ButtonVariant::Ghost)
                    .control_size(ControlSize::Small)
                    .shortcut("⌘R")
                    .disabled(s.scanning)
                    .on_press(|s: &mut App| s.scan())
                    .build(&k),
            );
    }
    let toolbar = Toolbar::new()
        .leading(
            text(title)
                .font(k.ty.ui_medium)
                .color(k.c.text_base)
                .truncate(),
        )
        .trailing(actions);
    let main = match &s.page {
        Page::Inventory => inventory_page(s, &k),
        Page::Peer(id) => peer_page(s, &k, id),
        Page::Received(id) => received_page(s, &k, id),
    };
    let split = SplitView::new(main)
        .sidebar(&s.sidebar, |s: &mut App| &mut s.sidebar, sidebar(s, &k))
        .toolbar(toolbar)
        .titlebar_inset(cx.titlebar_inset())
        .frame_inset(8.0)
        .toolbar_in_panel()
        .sidebar_toggle(SidebarToggle::new().in_header())
        .reduced_motion(cx.is_reduced_motion())
        .build(&k);
    dialogs(s, &k, &mut layer);
    let mut root = col().w_full().h_full().child(split);
    if let Some((msg, err)) = &s.toast {
        root = root.child(toast(&k, msg, *err));
    }
    rune_kit::root(root, layer)
}

fn toast(k: &Kit, msg: &str, error: bool) -> El {
    let c = if error { &k.c.danger } else { &k.c.success };
    let card = row()
        .key("toast")
        .max_w(420.0)
        .px(14.0)
        .py(10.0)
        .gap(10.0)
        .items_center()
        .radius(8.0)
        .fill(k.c.layer_01)
        .border(1.0, c.border)
        .child(el().size(8.0, 8.0).radius(4.0).fill(c.icon))
        .child(
            text(msg.to_string())
                .font(k.ty.ui)
                .color(k.c.text_base)
                .wrap()
                .shrink(),
        )
        .pin(Some(16.0), None, None, Some(16.0))
        .on_press(|s: &mut App| s.toast = None);
    k.elevate(card, &k.elevation.overlay)
}

fn sidebar(s: &App, k: &Kit) -> El {
    let set_label = match &s.store.active_set {
        Some(n) => format!("{} · {n}", s.name),
        None => s.name.clone(),
    };
    let mut sb = Sidebar::new().header(
        SidebarRow::new("This Mac")
            .subtitle(set_label)
            .icon(&rune_kit::glyphs::FOLDER)
            .height(44.0)
            .selected(s.page == Page::Inventory)
            .on_select(|s: &mut App, _| s.page = Page::Inventory)
            .build(k)
            .key("this-mac"),
    );
    let mut set_rows = Vec::new();
    for name in s.store.sets.keys() {
        let (n1, n2) = (name.clone(), name.clone());
        let active = s.store.active_set.as_deref() == Some(name.as_str());
        set_rows.push(
            SidebarRow::new(name.clone())
                .subtitle(if active {
                    "In use; changes are saved to it"
                } else {
                    "Click to use"
                })
                .height(44.0)
                .selected(active && s.page == Page::Inventory)
                .on_select(move |s: &mut App, _| s.load_set(&n1))
                .on_close(move |s: &mut App, _| s.confirm = Some(Confirm::DeleteSet(n2.clone())))
                .build(k)
                .key(format!("set/{name}")),
        );
    }
    if s.store.sets.is_empty() {
        set_rows.push(
            SidebarRow::new("No saved sets")
                .subtitle("Save what's ticked to reuse it")
                .height(44.0)
                .select_only()
                .build(k)
                .key("no-sets"),
        );
    }
    sb = sb.section(
        SidebarSection::new("Sets")
            .key("sets")
            .count(s.store.sets.len())
            .action(
                Button::new("Save as…")
                    .variant(ButtonVariant::GhostFaint)
                    .control_size(ControlSize::Small)
                    .on_press(|s: &mut App| {
                        let name = s.store.active_set.clone().unwrap_or_default();
                        s.save_set = Some(TextEdit::new(&name));
                    })
                    .build(k),
            )
            .rows(set_rows),
    );
    let mut rows = Vec::new();
    if let Some(e) = &s.net_error {
        rows.push(
            text(e.clone())
                .font(k.ty.small)
                .color(k.c.danger.fg)
                .wrap()
                .key("net-err"),
        );
    } else if s.peers.is_empty() {
        rows.push(
            SidebarRow::new("Looking for other Macs…")
                .subtitle("Not found? Use Connect… with its address")
                .height(44.0)
                .select_only()
                .build(k)
                .key("looking"),
        );
    }
    for p in &s.peers {
        let id = p.id.clone();
        let manual = p.id.starts_with("addr:");
        let subtitle = match s.reach.get(&p.id) {
            _ if !manual => p.addr.ip().to_string(),
            None => format!("{} · checking…", p.addr),
            Some(Ok(_)) => format!("{} · added by hand", p.addr),
            Some(Err(_)) => format!("{} · not answering", p.addr),
        };
        let mut r = SidebarRow::new(p.name.clone())
            .subtitle(subtitle)
            .height(44.0)
            .selected(s.page == Page::Peer(p.id.clone()))
            .on_select(move |s: &mut App, _| s.page = Page::Peer(id.clone()));
        if manual {
            let addr = p.addr;
            r = r.on_close(move |s: &mut App, _| s.forget_peer(addr));
        }
        rows.push(r.build(k).key(format!("peer/{}", p.id)));
    }
    if let Some(port) = s.port {
        let ips: Vec<String> = s.my_ips.iter().map(|ip| ip.to_string()).collect();
        let me = match (ips.is_empty(), port == net::PORT) {
            (true, _) => format!("This Mac listens on port {port}"),
            (false, true) => format!("This Mac's address: {}", ips.join(", ")),
            (false, false) => format!(
                "This Mac's address: {}",
                ips.iter()
                    .map(|ip| format!("{ip}:{port}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        rows.push(
            text(me)
                .font(k.ty.small)
                .color(k.c.text_faint)
                .wrap()
                .px(10.0)
                .py(4.0)
                .key("my-addr"),
        );
    }
    sb = sb.section(
        SidebarSection::new("Nearby Macs")
            .key("peers")
            .count(s.peers.len())
            .action(
                Button::new("Connect…")
                    .variant(ButtonVariant::GhostFaint)
                    .control_size(ControlSize::Small)
                    .on_press(|s: &mut App| s.connect = Some(TextEdit::new("")))
                    .build(k),
            )
            .rows(rows),
    );
    if !s.saved.is_empty() || s.receiving.is_some() {
        let mut rows = Vec::new();
        if let Some((from, bytes)) = &s.receiving {
            rows.push(
                SidebarRow::new(format!("Receiving from {from}…"))
                    .subtitle(human_size(bytes.load(Ordering::Relaxed)))
                    .height(44.0)
                    .select_only()
                    .build(k)
                    .key("receiving"),
            );
        }
        for p in &s.saved {
            let id = p.id.clone();
            rows.push(
                SidebarRow::new(p.manifest.from.clone())
                    .subtitle(format!(
                        "{} items · {}",
                        p.manifest.items.len(),
                        date(p.manifest.created)
                    ))
                    .height(44.0)
                    .selected(s.page == Page::Received(p.id.clone()))
                    .on_select(move |s: &mut App, _| s.open_received(&id))
                    .build(k)
                    .key(format!("saved/{}", p.id)),
            );
        }
        sb = sb.section(
            SidebarSection::new("Received")
                .key("received")
                .count(s.saved.len())
                .rows(rows),
        );
    }
    if let (Some(tag), false) = (&s.update, s.update_hidden) {
        sb = sb.footer(
            SidebarRow::new(format!("Update available: {tag}"))
                .icon(&rune_kit::glyphs::SPARKLE)
                .height(36.0)
                .on_select(|s: &mut App, _| s.confirm = Some(Confirm::Update))
                .build(k)
                .key("update-available"),
        );
    }
    sb.build(k)
}

fn manual_id(addr: &std::net::SocketAddr) -> String {
    format!("addr:{addr}")
}

/// `2026-11-12`, from unix seconds (UTC; good enough to tell packages apart).
fn date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn scroll(content: El) -> El {
    col()
        .w_full()
        .h_full()
        .min_h(0.0)
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .child(content)
}

/// The verification code, large enough to compare across a room.
fn big_code(k: &Kit) -> rune::tok::TextStyle {
    let mut t = k.ty.mono;
    t.size = 30.0;
    t.line_height = 38.0;
    t.weight = 600.0;
    t
}

fn heading(k: &Kit, t: impl Into<String>) -> El {
    text(t.into()).font(k.ty.ui_medium).color(k.c.text_base)
}

fn muted(k: &Kit, t: impl Into<String>) -> El {
    text(t.into()).font(k.ty.ui).color(k.c.text_muted).wrap()
}

fn summary(items: &[Item]) -> String {
    let apps = items
        .iter()
        .filter(|i| matches!(i.kind, Kind::Cask | Kind::MasApp))
        .count();
    let tools = items
        .iter()
        .filter(|i| matches!(i.kind, Kind::Formula | Kind::Tap))
        .count();
    let files: Vec<&Item> = items.iter().filter(|i| i.kind.has_files()).collect();
    let size: u64 = files.iter().filter_map(|i| i.size).sum();
    format!(
        "{apps} apps · {tools} tools · {} settings and folders ({})",
        files.len(),
        human_size(size)
    )
}

/// Items grouped by kind, each with a checkbox. `list` says whose selection they show.
fn item_list(s: &App, k: &Kit, items: &[Item], list: List, editable: bool) -> El {
    let mut c = col().w_full().gap(14.0);
    let is_received = list == List::Received;
    for kind in Kind::ALL {
        let group: Vec<&Item> = items.iter().filter(|i| i.kind == kind).collect();
        if group.is_empty() {
            continue;
        }
        let on = group.iter().filter(|i| s.is_on(list, i)).count();
        let collapsed = s.collapsed.contains(&(is_received, kind));
        let keys: Vec<(String, bool)> = group.iter().map(|i| (i.key(), i.default_on)).collect();
        let all = on == group.len();
        let head_keys = keys.clone();
        let mut head = row()
            .w_full()
            .gap(10.0)
            .items_center()
            .child(
                Checkbox::new(all)
                    .indeterminate(on > 0 && !all)
                    .disabled(!editable)
                    .on_toggle(move |s: &mut App| s.set_on(list, head_keys.clone(), !all))
                    .build(k),
            )
            .child(
                k.interactive(
                    row()
                        .gap(8.0)
                        .items_center()
                        .grow(1.0)
                        .child(heading(k, kind.title()))
                        .child(
                            text(format!("{on} of {}", group.len()))
                                .font(k.ty.small)
                                .color(k.c.text_faint),
                        )
                        .child(row().grow(1.0))
                        .child(
                            text(if collapsed { "Show" } else { "Hide" })
                                .font(k.ty.small)
                                .color(k.c.text_muted),
                        )
                        .on_press(move |s: &mut App| {
                            let key = (is_received, kind);
                            if !s.collapsed.remove(&key) {
                                s.collapsed.insert(key);
                            }
                        }),
                ),
            );
        head = head.key(format!("group/{kind:?}"));
        c = c.child(head);
        if kind == Kind::ManualApp && !collapsed {
            c = c.child(muted(
                k,
                "macpack can't install these. Selected ones are listed as a checklist on the other Mac.",
            ));
        }
        if collapsed {
            continue;
        }
        let mut rows = col().w_full().gap(2.0).pl(26.0);
        for it in group {
            let key = it.key();
            let (k2, default) = (key.clone(), it.default_on);
            let checked = s.is_on(list, it);
            let mut r = row().w_full().gap(10.0).items_center().py(3.0).child(
                Checkbox::new(checked)
                    .label(it.label.clone())
                    .disabled(!editable)
                    .on_toggle(move |s: &mut App| {
                        s.set_on(list, vec![(k2.clone(), default)], !checked)
                    })
                    .build(k),
            );
            if it.sensitive {
                r = r.child(Badge::new("secrets").variant(BadgeVariant::Accent).build(k));
            }
            r = r.child(
                text(it.detail.clone())
                    .font(k.ty.small)
                    .color(k.c.text_faint)
                    .truncate()
                    .grow(1.0)
                    .min_w(0.0),
            );
            let size = match it.size {
                _ if it.size_over => Some(format!("{}+", human_size(inventory::BIG))),
                Some(sz) => Some(human_size(sz)),
                None => None,
            };
            if let Some(sz) = size {
                r = r.child(text(sz).font(k.ty.small).color(k.c.text_muted));
            }
            if kind == Kind::Folder && list == List::Inventory {
                let rel = it.id.clone();
                r = r.child(
                    Button::new("Remove")
                        .variant(ButtonVariant::GhostFaint)
                        .control_size(ControlSize::Small)
                        .on_press(move |s: &mut App| s.remove_folder(&rel))
                        .build(k),
                );
            }
            rows = rows.child(r.key(key));
        }
        c = c.child(rows);
    }
    c
}

/// Each scan step with a spinner while it runs and a check when it's done.
fn scan_steps(s: &App, k: &Kit) -> El {
    let mut c = col().w_full().gap(6.0);
    if s.scan_steps.is_empty() {
        c = c.child(
            row()
                .gap(8.0)
                .items_center()
                .child(Spinner::new().build(k))
                .child(muted(k, "Starting…")),
        );
    }
    for (name, detail, done) in &s.scan_steps {
        let mark = if *done {
            text("✓").font(k.ty.ui).color(k.c.success.fg).w(16.0)
        } else {
            Spinner::new().build(k).w(16.0)
        };
        c = c.child(
            row()
                .w_full()
                .gap(8.0)
                .items_center()
                .child(mark)
                .child(text(name.to_string()).font(k.ty.ui).color(k.c.text_base))
                .child(
                    text(detail.clone())
                        .font(k.ty.small)
                        .color(k.c.text_faint)
                        .truncate()
                        .grow(1.0)
                        .min_w(0.0),
                )
                .key(format!("step/{name}")),
        );
    }
    c
}

fn inventory_page(s: &App, k: &Kit) -> El {
    let Some(inv) = &s.inventory else {
        return col().w_full().h_full().center().child(
            col()
                .w(420.0)
                .gap(12.0)
                .child(heading(k, "Taking inventory of this Mac…"))
                .child(scan_steps(s, k)),
        );
    };
    let selected = s.selection();
    let mut c = col()
        .w_full()
        .padding(20.0)
        .gap(16.0)
        .child(
            col()
                .gap(4.0)
                .child(heading(k, "What to bring to your new Mac"))
                .child(muted(k, summary(&selected)))
                .child(muted(
                    k,
                    "Apps are reinstalled on the other Mac with Homebrew and the App Store, never copied. \
                     Settings, dotfiles and folders are copied, and anything they'd replace is backed up first.",
                )),
        );
    if s.scanning {
        c = c.child(
            col()
                .w_full()
                .padding(12.0)
                .gap(8.0)
                .radius(8.0)
                .fill(k.c.layer_01)
                .child(muted(
                    k,
                    format!(
                        "Rescanning. Showing the scan from {} until it finishes.",
                        date(inv.scanned)
                    ),
                ))
                .child(scan_steps(s, k)),
        );
    }
    for n in &inv.notes {
        c = c.child(
            text(n.clone())
                .font(k.ty.small)
                .color(k.c.warning.fg)
                .wrap(),
        );
    }
    c = c.child(item_list(s, k, &inv.items, List::Inventory, true));
    scroll(c)
}

fn peer_page(s: &App, k: &Kit, id: &str) -> El {
    let Some(peer) = s.peers.iter().find(|p| p.id == id) else {
        return col().w_full().h_full().center().child(muted(
            k,
            "That Mac has gone away. Is macpack still open on it?",
        ));
    };
    let selected = s.selection();
    if let Some(Err(e)) = s.reach.get(id) {
        let addr = peer.addr;
        return col()
            .w_full()
            .max_w(560.0)
            .padding(24.0)
            .gap(14.0)
            .child(heading(k, peer.addr.to_string()))
            .child(text(e.clone()).font(k.ty.ui).color(k.c.danger.fg).wrap())
            .child(muted(
                k,
                "Check that macpack is open on that Mac and the address matches what it shows under Nearby Macs. \
                 If it still doesn't answer, allow macpack in System Settings → Privacy & Security → Local Network, \
                 and under Network → Firewall, on that Mac.",
            ))
            .child(
                row().gap(8.0).child(
                    Button::new("Check again")
                        .variant(ButtonVariant::Contrast)
                        .on_press(move |s: &mut App| s.check_peer(addr))
                        .build(k),
                ),
            );
    }
    let mut c = col()
        .w_full()
        .max_w(560.0)
        .padding(24.0)
        .gap(14.0)
        .child(heading(k, peer.name.clone()))
        .child(muted(
            k,
            format!("{} · port {}", peer.addr.ip(), peer.addr.port()),
        ))
        .child(muted(k, format!("Package: {}", summary(&selected))));
    let t = s.sending.as_ref().filter(|t| t.peer == id);
    let busy = t.is_some_and(|t| t.result.is_none());
    match t {
        None => {}
        Some(t) => {
            let status = match (&t.result, &t.code, t.accepted) {
                (Some(Ok(true)), _, _) => "Sent. Review and apply it on the other Mac.".to_string(),
                (Some(Ok(false)), _, _) => "The other Mac declined.".to_string(),
                (Some(Err(e)), _, _) => format!("Failed: {e}"),
                (None, None, _) => "Connecting…".to_string(),
                (None, Some(_), false) => {
                    "Check that the other Mac shows the same code, and accept there.".to_string()
                }
                (None, Some(_), true) => {
                    format!("Sending… {}", human_size(t.bytes.load(Ordering::Relaxed)))
                }
            };
            let mut card = col()
                .w_full()
                .padding(16.0)
                .gap(10.0)
                .radius(8.0)
                .fill(k.c.layer_01)
                .border(1.0, k.c.border_base);
            if let Some(code) = &t.code {
                card = card
                    .child(
                        text("Verification code")
                            .font(k.ty.small)
                            .color(k.c.text_muted),
                    )
                    .child(text(code.clone()).font(big_code(k)).color(k.c.text_base));
            }
            let mut line = row().gap(10.0).items_center();
            if busy {
                line = line.child(Spinner::new().build(k));
            }
            let err = matches!(t.result, Some(Err(_)));
            line = line.child(
                text(status)
                    .font(k.ty.ui)
                    .color(if err { k.c.danger.fg } else { k.c.text_base })
                    .wrap()
                    .shrink(),
            );
            c = c.child(card.child(line));
        }
    }
    let p = peer.clone();
    c = c.child(
        row().child(
            Button::new(format!("Send to {}", peer.name))
                .variant(ButtonVariant::Contrast)
                .disabled(busy || selected.is_empty() || s.inventory.is_none())
                .on_press(move |s: &mut App| s.send_to(&p))
                .build(k),
        ),
    );
    scroll(c)
}

fn received_page(s: &App, k: &Kit, id: &str) -> El {
    let Some(saved) = s.saved.iter().find(|p| p.id == id) else {
        return col();
    };
    let m = &saved.manifest;
    let chosen: Vec<Item> = m
        .items
        .iter()
        .filter(|i| s.apply_keys.contains(&i.key()))
        .cloned()
        .collect();
    let mut c = col().w_full().padding(20.0).gap(16.0).child(
        col()
            .gap(4.0)
            .child(heading(k, format!("From {} · {}", m.from, date(m.created))))
            .child(muted(k, format!("Apply: {}", summary(&chosen)))),
    );
    let id2 = id.to_string();
    let actions = row()
        .gap(8.0)
        .child(
            Button::new("Apply to this Mac…")
                .variant(ButtonVariant::Contrast)
                .disabled(s.applying || chosen.is_empty())
                .on_press(|s: &mut App| s.confirm = Some(Confirm::Apply))
                .build(k),
        )
        .child(
            Button::new("Delete package")
                .variant(ButtonVariant::Ghost)
                .disabled(s.applying)
                .on_press(move |s: &mut App| s.confirm = Some(Confirm::Delete(id2.clone())))
                .build(k),
        );
    c = c.child(actions);
    if s.applying || !s.apply_log.is_empty() {
        c = c.child(apply_log(s, k));
    }
    c = c.child(item_list(s, k, &m.items, List::Received, !s.applying));
    scroll(c)
}

fn apply_log(s: &App, k: &Kit) -> El {
    let mut log = col()
        .w_full()
        .padding(12.0)
        .gap(4.0)
        .radius(8.0)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base);
    // Long Homebrew output: keep the step lines and the last few output lines of each step.
    let mut tail: Vec<&str> = Vec::new();
    let flush = |log: El, tail: &mut Vec<&str>| {
        let skip = tail.len().saturating_sub(6);
        let mut log = log;
        for l in tail.drain(..).skip(skip) {
            log = log.child(
                text(l.to_string())
                    .font(k.ty.mono)
                    .color(k.c.text_muted)
                    .truncate(),
            );
        }
        log
    };
    for entry in &s.apply_log {
        match entry {
            Log::Line(l) => tail.push(l),
            Log::Step(t) => {
                log = flush(log, &mut tail);
                log = log.child(heading(k, t.clone()).pt(4.0));
            }
            Log::Ok(m) => {
                log = flush(log, &mut tail);
                log = log.child(
                    text(format!("✓ {m}"))
                        .font(k.ty.ui)
                        .color(k.c.success.fg)
                        .wrap(),
                );
            }
            Log::Fail(m) => {
                log = flush(log, &mut tail);
                log = log.child(
                    text(format!("✗ {m}"))
                        .font(k.ty.ui)
                        .color(k.c.danger.fg)
                        .wrap(),
                );
            }
        }
    }
    log = flush(log, &mut tail);
    if s.applying {
        log = log.child(
            row()
                .gap(8.0)
                .items_center()
                .child(Spinner::new().build(k))
                .child(muted(k, "Working…")),
        );
    }
    log.key("apply-log")
}

// ------------------------------------------------------------------------------------- dialogs

#[allow(clippy::too_many_arguments)]
fn modal(
    key: &str,
    title: &str,
    description: Option<&str>,
    body: Vec<El>,
    actions: Vec<El>,
    k: &Kit,
    layer: &mut Vec<El>,
    width: f32,
) {
    let mut footer = row().w_full().gap(8.0).pt(4.0).child(row().grow(1.0));
    for a in actions {
        footer = footer.child(a);
    }
    let mut content = col().w_full().px(16.0).pb(16.0).gap(12.0);
    if let Some(desc) = description {
        content = content.child(
            text(desc.to_string())
                .font(k.ty.ui)
                .color(k.c.text_muted)
                .wrap()
                .mt(-6.0),
        );
    }
    let content = content.children(body).child(footer);
    Dialog::new(key, title)
        .open(true)
        .fit()
        .width(width)
        .child(content)
        .on_close(|s: &mut App| {
            s.add_folder = None;
            s.save_set = None;
            s.connect = None;
            s.confirm = None;
        })
        .build(k, layer);
}

fn cancel(k: &Kit) -> El {
    Button::new("Cancel")
        .variant(ButtonVariant::Ghost)
        .on_press(|s: &mut App| {
            s.add_folder = None;
            s.save_set = None;
            s.connect = None;
            s.confirm = None;
        })
        .build(k)
}

fn dialogs(s: &App, k: &Kit, layer: &mut Vec<El>) {
    if let Some(inc) = &s.incoming {
        let body = vec![
            col()
                .w_full()
                .padding(14.0)
                .gap(6.0)
                .radius(8.0)
                .fill(k.c.layer_01)
                .child(
                    text("Verification code")
                        .font(k.ty.small)
                        .color(k.c.text_muted),
                )
                .child(
                    text(inc.code.clone())
                        .font(big_code(k))
                        .color(k.c.text_base),
                ),
            muted(k, format!("Package: {}", summary(&inc.manifest.items))),
            muted(
                k,
                "Accept only if the sending Mac shows the same code. Nothing is applied until you review the package and choose Apply.",
            ),
        ];
        let decline = Button::new("Decline")
            .variant(ButtonVariant::Ghost)
            .on_press(|s: &mut App| s.answer(false))
            .build(k);
        let accept = Button::new("Codes match, accept")
            .variant(ButtonVariant::Contrast)
            .on_press(|s: &mut App| s.answer(true))
            .build(k);
        let title = format!("{} wants to send you its setup", inc.from);
        // Dismissing the dialog declines.
        Dialog::new("incoming", &title)
            .open(true)
            .fit()
            .width(480.0)
            .child(
                col()
                    .w_full()
                    .px(16.0)
                    .pb(16.0)
                    .gap(12.0)
                    .children(body)
                    .child(
                        row()
                            .w_full()
                            .gap(8.0)
                            .pt(4.0)
                            .child(row().grow(1.0))
                            .child(decline)
                            .child(accept),
                    ),
            )
            .on_close(|s: &mut App| s.answer(false))
            .build(k, layer);
        return;
    }
    if let Some(edit) = &s.connect {
        let input = TextInput::new(edit)
            .placeholder("192.168.1.20")
            .width(None)
            .on_edit(|s: &mut App| s.connect.as_mut().expect("dialog open"))
            .on_submit(|s: &mut App, _| s.connect())
            .build(k);
        let go = Button::new("Connect")
            .variant(ButtonVariant::Contrast)
            .on_press(|s: &mut App| s.connect())
            .build(k);
        modal(
            "connect",
            "Connect by address",
            Some(
                "For when the Macs don't find each other. The other Mac shows its address at the bottom of Nearby Macs.",
            ),
            vec![input],
            vec![cancel(k), go],
            k,
            layer,
            440.0,
        );
    }
    if let Some(edit) = &s.save_set {
        let input = TextInput::new(edit)
            .placeholder("Work laptop")
            .width(None)
            .on_edit(|s: &mut App| s.save_set.as_mut().expect("dialog open"))
            .on_submit(|s: &mut App, _| s.save_set())
            .build(k);
        let save = Button::new("Save")
            .variant(ButtonVariant::Contrast)
            .on_press(|s: &mut App| s.save_set())
            .build(k);
        modal(
            "save-set",
            "Save selection as a set",
            Some(
                "Keeps what's ticked and the folders you added under a name, to use again later. Changes you make while a set is in use are saved to it. Using an existing name replaces that set.",
            ),
            vec![input],
            vec![cancel(k), save],
            k,
            layer,
            460.0,
        );
    }
    if let Some(edit) = &s.add_folder {
        let input = TextInput::new(edit)
            .placeholder("~/projects")
            .width(None)
            .on_edit(|s: &mut App| s.add_folder.as_mut().expect("dialog open"))
            .on_submit(|s: &mut App, _| s.add_folder())
            .build(k);
        let add = Button::new("Add")
            .variant(ButtonVariant::Contrast)
            .on_press(|s: &mut App| s.add_folder())
            .build(k);
        modal(
            "add-folder",
            "Add a folder",
            Some(
                "A folder in your home folder to copy to the other Mac. node_modules, .venv and __pycache__ are left out.",
            ),
            vec![input],
            vec![cancel(k), add],
            k,
            layer,
            460.0,
        );
    }
    match &s.confirm {
        Some(Confirm::Apply) => {
            let chosen: Vec<&Item> = s
                .saved
                .iter()
                .flat_map(|p| &p.manifest.items)
                .filter(|i| s.apply_keys.contains(&i.key()))
                .collect();
            let files = chosen.iter().filter(|i| i.kind.has_files()).count();
            let installs = chosen
                .iter()
                .filter(|i| {
                    matches!(
                        i.kind,
                        Kind::Tap | Kind::Formula | Kind::Cask | Kind::MasApp
                    )
                })
                .count();
            let mut body = vec![muted(
                k,
                format!(
                    "Copies {files} settings and folders into your home folder (existing files are moved to a backup first), then installs {installs} apps, tools with Homebrew."
                ),
            )];
            if chosen.iter().any(|i| i.kind == Kind::MasApp) {
                body.push(muted(
                    k,
                    "App Store apps need you to be signed in to the App Store.",
                ));
            }
            body.push(muted(
                k,
                "Some Homebrew apps ask for your password; if one can't, the log says so and you can rerun Apply from a terminal session.",
            ));
            let go = Button::new("Apply")
                .variant(ButtonVariant::Contrast)
                .on_press(|s: &mut App| s.apply())
                .build(k);
            modal(
                "apply",
                "Apply this package?",
                None,
                body,
                vec![cancel(k), go],
                k,
                layer,
                480.0,
            );
        }
        Some(Confirm::DeleteSet(name)) => {
            let name = name.clone();
            let title = format!("Delete the set \u{201c}{name}\u{201d}?");
            let go = Button::new("Delete")
                .variant(ButtonVariant::Danger)
                .on_press(move |s: &mut App| s.delete_set(&name))
                .build(k);
            modal(
                "delete-set",
                &title,
                Some("What's ticked now stays as it is."),
                vec![],
                vec![cancel(k), go],
                k,
                layer,
                420.0,
            );
        }
        Some(Confirm::Delete(id)) => {
            let id = id.clone();
            let go = Button::new("Delete")
                .variant(ButtonVariant::Danger)
                .on_press(move |s: &mut App| s.delete_received(&id))
                .build(k);
            modal(
                "delete",
                "Delete this package?",
                Some(
                    "It holds copies of your settings and keys. Applying it again needs a new transfer.",
                ),
                vec![],
                vec![cancel(k), go],
                k,
                layer,
                420.0,
            );
        }
        Some(Confirm::Update) => {
            let Some(tag) = s.update.clone() else { return };
            let notes = format!("https://github.com/{}/releases/tag/{tag}", update::REPO);
            let brew = update::brew_prefix().is_some();
            let mut body = vec![muted(
                k,
                format!(
                    "macpack {tag} is available. You have v{}.",
                    update::current()
                ),
            )];
            if s.updating {
                body.push(
                    row()
                        .gap(10.0)
                        .items_center()
                        .child(Spinner::new().build(k))
                        .child(muted(k, "Updating with Homebrew…")),
                );
            } else if !brew {
                body.push(muted(
                    k,
                    "This copy wasn't installed with Homebrew, so update it the way you installed it.",
                ));
            }
            let open_notes = Button::new("Release notes")
                .variant(ButtonVariant::Ghost)
                .on_press_tx(move |_: &mut App, tx| {
                    let _ = tx.open_url(&notes);
                })
                .build(k);
            let skip_tag = tag.clone();
            let skip = Button::new("Skip this version")
                .variant(ButtonVariant::Ghost)
                .disabled(s.updating)
                .on_press(move |s: &mut App| {
                    s.store.skipped_version = Some(skip_tag.clone());
                    s.save();
                    s.update = None;
                    s.confirm = None;
                })
                .build(k);
            let later = Button::new("Later")
                .variant(ButtonVariant::Ghost)
                .disabled(s.updating)
                .on_press(|s: &mut App| {
                    s.update_hidden = true;
                    s.confirm = None;
                })
                .build(k);
            let mut actions = vec![open_notes, skip, later];
            if brew {
                actions.push(
                    Button::new("Update and restart")
                        .variant(ButtonVariant::Contrast)
                        .disabled(s.updating)
                        .on_press(|s: &mut App| s.run_update())
                        .build(k),
                );
            }
            modal(
                "update",
                "Update macpack",
                None,
                body,
                actions,
                k,
                layer,
                460.0,
            );
        }
        Some(Confirm::InstallApp) => {
            let never = Button::new("Don't ask again")
                .variant(ButtonVariant::Ghost)
                .on_press(|s: &mut App| {
                    s.confirm = None;
                    s.store.skip_app_prompt = true;
                    s.save();
                    s.notify("You can add it later with `macpack install-app`", false);
                })
                .build(k);
            let later = Button::new("Not now")
                .variant(ButtonVariant::Ghost)
                .on_press(|s: &mut App| s.confirm = None)
                .build(k);
            let add = Button::new("Add to Applications")
                .variant(ButtonVariant::Contrast)
                .on_press(|s: &mut App| s.install_app())
                .build(k);
            let detail = muted(
                k,
                "Creates ~/Applications/macpack.app so you can open macpack from Spotlight, Launchpad or the Dock. \
                 It runs the macpack you already have installed, so `brew upgrade` keeps it current. \
                 Same as running `macpack install-app`.",
            );
            modal(
                "install-app",
                "Add macpack to your Applications?",
                None,
                vec![detail],
                vec![never, later, add],
                k,
                layer,
                460.0,
            );
        }
        None => {}
    }
}

// ---------------------------------------------------------------------------------------- demo

fn demo_item(kind: Kind, id: &str, label: &str, detail: &str, size: Option<u64>) -> Item {
    Item {
        kind,
        id: id.into(),
        label: label.into(),
        detail: detail.into(),
        size,
        size_over: false,
        default_on: kind != Kind::Defaults,
        sensitive: id == ".ssh" || id == ".aws",
    }
}

fn demo_items() -> Vec<Item> {
    vec![
        demo_item(
            Kind::Cask,
            "signal",
            "Signal",
            "Instant messaging application focusing on security",
            None,
        ),
        demo_item(
            Kind::Cask,
            "visual-studio-code",
            "Microsoft Visual Studio Code",
            "Open-source code editor",
            None,
        ),
        demo_item(Kind::Cask, "zed", "Zed", "Multiplayer code editor", None),
        demo_item(
            Kind::Cask,
            "1password",
            "1Password",
            "Password manager",
            None,
        ),
        demo_item(Kind::MasApp, "497799835", "Xcode", "", None),
        demo_item(Kind::Formula, "gh", "gh", "", None),
        demo_item(Kind::Formula, "ripgrep", "ripgrep", "", None),
        demo_item(Kind::Tap, "vangheem/tap", "vangheem/tap", "", None),
        demo_item(Kind::Dotfile, ".zshrc", "~/.zshrc", "", Some(2_400)),
        demo_item(Kind::Dotfile, ".gitconfig", "~/.gitconfig", "", Some(612)),
        demo_item(
            Kind::Dotfile,
            ".ssh",
            "~/.ssh",
            "SSH keys and config",
            Some(14_200),
        ),
        demo_item(
            Kind::Dotfile,
            ".aws",
            "~/.aws",
            "Contains credentials",
            Some(1_100),
        ),
        demo_item(
            Kind::Dotfile,
            ".config/zed",
            "~/.config/zed",
            "",
            Some(48_000),
        ),
        demo_item(
            Kind::Folder,
            "projects",
            "~/projects",
            "",
            Some(812_000_000),
        ),
        demo_item(
            Kind::Defaults,
            "com.apple.dock",
            "Dock",
            "com.apple.dock",
            None,
        ),
        demo_item(
            Kind::ManualApp,
            "Logi Options+.app",
            "Logi Options+",
            "com.logi.optionsplus",
            None,
        ),
    ]
}

fn demo(s: &mut App) {
    s.name = "Jane's MacBook Pro".into();
    s.inventory = Some(Inventory {
        items: demo_items(),
        notes: Vec::new(),
        scanned: 1_794_528_000,
    });
    s.peers = vec![Peer {
        id: "a1b2c3".into(),
        name: "Jane's Mac Studio".into(),
        addr: "192.168.1.24:52114".parse().unwrap(),
    }];
    s.saved = vec![Saved {
        id: "1".into(),
        manifest: Manifest {
            format: package::FORMAT,
            from: "Jane's old MacBook Air".into(),
            created: 1_794_528_000,
            items: demo_items(),
        },
    }];
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if appbundle::cli(&args) {
        return;
    }
    match args.get(1).map(String::as_str) {
        // `macpack brewfile`: the Brewfile a package from this Mac would install.
        Some("brewfile") => {
            let inv = inventory::installs(&|_| {});
            let refs: Vec<&Item> = inv.items.iter().collect();
            print!("{}", package::brewfile(&refs));
            return;
        }
        // `macpack inventory`: everything on this Mac, as JSON.
        Some("inventory") => {
            let inv = inventory::scan(&Store::load().folders, &|p| {
                if let inventory::Progress::Done(n, d) = p {
                    eprintln!("{n}: {d}");
                }
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&inv.items).unwrap_or_default()
            );
            return;
        }
        // `macpack peers`: what discovery and the subnet sweep find, for troubleshooting.
        Some("peers") => {
            let store = Store::load();
            let (tx, rx) = channel();
            let _mdns = discovery::start(
                &format!("{}-cli", store.device_id),
                "macpack peers",
                0,
                move |p| {
                    let _ = tx.send(p);
                },
            );
            for p in net::sweep(&net::local_ips()) {
                println!("sweep: {} at {}", p.name, p.addr);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut seen = Vec::new();
            while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
                if let Ok(p) = rx.recv_timeout(left) {
                    seen = p;
                }
            }
            for p in seen {
                println!("mdns:  {} at {}", p.name, p.addr);
            }
            return;
        }
        // `macpack ping 192.168.1.20`: checks that macpack answers at an address.
        Some("ping") => {
            let Some(addr) = args.get(2).and_then(|a| net::parse_addr(a)) else {
                eprintln!("usage: macpack ping <address>[:port]");
                std::process::exit(2);
            };
            match net::ping(addr) {
                Ok((name, version)) => println!("{name} answered at {addr} (macpack {version})"),
                Err(e) => {
                    eprintln!("macpack: {e:#}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Some("--version" | "-V") => {
            println!("macpack {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        _ => {}
    }
    let _ = rune::set_app_icon(include_bytes!("../assets/icon.png").to_vec());
    let spec = AppSpec {
        scenes: &[
            ("demo", demo),
            ("send", |s: &mut App| {
                demo(s);
                s.page = Page::Peer("a1b2c3".into());
                s.sending = Some(Sending {
                    peer: "a1b2c3".into(),
                    code: Some("482 913".into()),
                    accepted: false,
                    bytes: Arc::new(AtomicU64::new(0)),
                    result: None,
                });
            }),
            ("scanning", |s: &mut App| {
                demo(s);
                s.inventory = None;
                s.scanning = true;
                s.scan_steps = vec![
                    ("Homebrew taps", "5 found".into(), true),
                    ("Settings and dotfiles", "~/.config/zed".into(), false),
                    ("Homebrew formulae", "35 found".into(), true),
                    ("Apps from Homebrew", String::new(), false),
                ];
            }),
            ("sets", |s: &mut App| {
                demo(s);
                s.store.save_set("Work laptop");
                s.store.sets.insert("Personal".into(), Default::default());
                s.save_set = Some(TextEdit::new("Work laptop"));
            }),
            ("incoming", |s: &mut App| {
                demo(s);
                let (reply, _) = channel();
                s.incoming = Some(Incoming {
                    from: "Jane's old MacBook Air".into(),
                    code: "482 913".into(),
                    manifest: s.saved[0].manifest.clone(),
                    reply,
                });
            }),
            ("received", |s: &mut App| {
                demo(s);
                s.open_received("1");
                s.apply_log = vec![
                    Log::Step("Settings, dotfiles and folders".into()),
                    Log::Ok("Wrote 1,204 files".into()),
                    Log::Step("Install apps and tools with Homebrew".into()),
                    Log::Line("Installing signal".into()),
                    Log::Line("Installing zed".into()),
                ];
                s.applying = true;
            }),
        ],
        setup: Some(setup),
        poll: Some(poll),
        on_key: Some(on_key),
        fonts: rune_theme_opencode::FONTS,
        families: rune_theme_opencode::FAMILIES,
        min_size: Some((820.0, 540.0)),
        ..AppSpec::new("macpack", (1180.0, 800.0), init, view)
    };
    let chrome = Chrome {
        full_size_content: true,
        traffic_lights: Some((16.0, 25.0)),
        drag_regions: true,
    };
    rune::App::new(spec).chrome(chrome).modifier_keys().run();
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_dates() {
        assert_eq!(super::date(0), "1970-01-01");
        assert_eq!(super::date(1_794_528_000), "2026-11-13");
    }
}
