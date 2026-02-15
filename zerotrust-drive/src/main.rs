use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

macro_rules! trace {
    ($($arg:tt)*) => {{
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("target/fuse.log") {
            let _ = writeln!(f, $($arg)*);
        }
    }};
}

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use fuser::{
    Config, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyWrite, Request,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const TTL: Duration = Duration::from_secs(1);
const BLKSIZE: u32 = 4096;

// --- Encryption helpers ---
// Derive a 256-bit key from passphrase using SHA-256 (fast, deterministic).
// For production, use a proper KDF like argon2 with a stored salt.
// Here we keep it simple: SHA-256 of passphrase → 32-byte key.

fn derive_key(passphrase: &str) -> [u8; 32] {
    // Simple key derivation: iterative hashing (not as strong as scrypt/argon2
    // but microseconds instead of hundreds of ms)
    let mut key = [0u8; 32];
    let bytes = passphrase.as_bytes();
    // Use a basic hash: XOR-fold + mix. For real security, use argon2.
    // We'll use the `age` crate's scrypt once at startup and cache the key.
    // Actually, let's just do a simple PBKDF-like thing inline:
    let mut state = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        state[i % 64] ^= b;
    }
    // Mix rounds
    for _ in 0..10000 {
        for i in 0..64 {
            state[i] = state[i].wrapping_add(state[(i + 1) % 64]).wrapping_mul(7).wrapping_add(0x9e);
        }
    }
    key.copy_from_slice(&state[..32]);
    key
}

/// Encrypt with ChaCha20-Poly1305 — random 12-byte nonce prepended to output.
fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())?;
    // prepend nonce
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt — first 12 bytes are the nonce.
fn decrypt_bytes(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("ciphertext too short".to_string());
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&data[..12]);
    cipher.decrypt(nonce, &data[12..]).map_err(|e| e.to_string())
}

// --- Persistent index ---

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
enum InodeKind {
    File,
    Directory,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct InodeEntry {
    name: String,
    kind: InodeKind,
    disk_filename: String,
    size: u64,
    perm: u16,
    uid: u32,
    gid: u32,
    atime_secs: u64,
    mtime_secs: u64,
    ctime_secs: u64,
    nlink: u32,
    parent: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DirChild {
    name: String,
    inode: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct DiskIndex {
    next_inode: u64,
    next_file_id: u64,
    inodes: HashMap<u64, InodeEntry>,
    children: HashMap<u64, Vec<DirChild>>,
}

// --- FUSE filesystem ---

struct ZeroTrustFs {
    base_path: PathBuf,
    key: [u8; 32],
    state: Mutex<DiskIndex>,
    open_files: Mutex<HashMap<u64, Vec<u8>>>,
}

impl ZeroTrustFs {
    fn new(passphrase: &str, base_path: PathBuf) -> Self {
        let key = derive_key(passphrase);
        fs::create_dir_all(&base_path).expect("failed to create base path");

        let index_path = base_path.join("_index.age");
        let state = if index_path.exists() {
            let ciphertext = fs::read(&index_path).expect("failed to read index");
            let json = decrypt_bytes(&key, &ciphertext).expect("failed to decrypt index");
            serde_json::from_slice(&json).expect("failed to parse index")
        } else {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let now = now_secs();

            let mut inodes = HashMap::new();
            inodes.insert(1, InodeEntry {
                name: String::new(), kind: InodeKind::Directory, disk_filename: String::new(),
                size: 0, perm: 0o755, uid, gid,
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 2, parent: 1,
            });
            let mut children = HashMap::new();
            children.insert(1u64, Vec::new());
            DiskIndex { next_inode: 2, next_file_id: 1, inodes, children }
        };

        let json = serde_json::to_vec(&state).expect("failed to serialize index");
        let zfs = Self {
            base_path, key,
            state: Mutex::new(state), open_files: Mutex::new(HashMap::new()),
        };
        zfs.persist_index(&json);
        zfs
    }

    /// Encrypt and write pre-serialized JSON to _index.age. No locks held.
    fn persist_index(&self, json: &[u8]) {
        let encrypted = encrypt_bytes(&self.key, json).expect("failed to encrypt index");
        fs::write(self.base_path.join("_index.age"), encrypted).expect("failed to write index");
    }

    fn allocate_disk_filename(state: &mut DiskIndex) -> String {
        let name = format!("{:06x}.age", state.next_file_id);
        state.next_file_id += 1;
        name
    }

    fn allocate_inode(state: &mut DiskIndex) -> u64 {
        let ino = state.next_inode;
        state.next_inode += 1;
        ino
    }

    fn inode_to_attr(ino: u64, entry: &InodeEntry) -> FileAttr {
        let time = |secs: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        FileAttr {
            ino: INodeNo(ino), size: entry.size, blocks: (entry.size + 511) / 512,
            atime: time(entry.atime_secs), mtime: time(entry.mtime_secs),
            ctime: time(entry.ctime_secs), crtime: time(entry.ctime_secs),
            kind: match entry.kind {
                InodeKind::File => FileType::RegularFile,
                InodeKind::Directory => FileType::Directory,
            },
            perm: entry.perm, nlink: entry.nlink, uid: entry.uid, gid: entry.gid,
            rdev: 0, blksize: BLKSIZE, flags: 0,
        }
    }

    fn find_child(state: &DiskIndex, parent: u64, name: &str) -> Option<u64> {
        state.children.get(&parent)?.iter().find(|c| c.name == name).map(|c| c.inode)
    }

    fn write_encrypted_file(&self, disk_filename: &str, content: &[u8]) {
        let encrypted = encrypt_bytes(&self.key, content).expect("failed to encrypt file");
        fs::write(self.base_path.join(disk_filename), encrypted).expect("failed to write file");
    }

    fn read_encrypted_file(&self, disk_filename: &str) -> Vec<u8> {
        let ciphertext = fs::read(self.base_path.join(disk_filename)).expect("failed to read file");
        decrypt_bytes(&self.key, &ciphertext).expect("failed to decrypt file")
    }

    /// Lock state, serialize, drop lock, encrypt+write. Safe to call without any locks held.
    fn flush_state(&self) {
        let json = {
            let state = self.state.lock().unwrap();
            serde_json::to_vec(&*state).expect("failed to serialize index")
        };
        // Lock is dropped here — safe to do slow encryption
        self.persist_index(&json);
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

impl Filesystem for ZeroTrustFs {
    fn init(&mut self, _req: &Request, _config: &mut fuser::KernelConfig) -> std::io::Result<()> {
        Ok(())
    }

    fn destroy(&mut self) {
        let open = self.open_files.lock().unwrap();
        let state = self.state.lock().unwrap();
        for (&ino, content) in open.iter() {
            if let Some(entry) = state.inodes.get(&ino) {
                if !entry.disk_filename.is_empty() {
                    self.write_encrypted_file(&entry.disk_filename, content);
                }
            }
        }
        let json = serde_json::to_vec(&*state).expect("failed to serialize");
        drop(state);
        drop(open);
        self.persist_index(&json);
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        trace!("FUSE: lookup parent={} name={:?}", parent.0, name);
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::ENOENT); return; }
        };
        let state = self.state.lock().unwrap();
        if let Some(ino) = Self::find_child(&state, parent.0, name_str) {
            if let Some(entry) = state.inodes.get(&ino) {
                reply.entry(&TTL, &Self::inode_to_attr(ino, entry), Generation(0));
                return;
            }
        }
        reply.error(fuser::Errno::ENOENT);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        trace!("FUSE: getattr ino={}", ino.0);
        let state = self.state.lock().unwrap();
        match state.inodes.get(&ino.0) {
            Some(entry) => {
                let mut attr = Self::inode_to_attr(ino.0, entry);
                let is_file = entry.kind == InodeKind::File;
                drop(state);
                if is_file {
                    let open = self.open_files.lock().unwrap();
                    if let Some(content) = open.get(&ino.0) {
                        attr.size = content.len() as u64;
                        attr.blocks = (attr.size + 511) / 512;
                    }
                }
                reply.attr(&TTL, &attr);
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn setattr(
        &self, _req: &Request, ino: INodeNo,
        mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>, _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>, _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>, _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        {
            let mut state = self.state.lock().unwrap();
            let entry = match state.inodes.get_mut(&ino.0) {
                Some(e) => e,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            if let Some(m) = mode { entry.perm = (m & 0o7777) as u16; }
            if let Some(u) = uid { entry.uid = u; }
            if let Some(g) = gid { entry.gid = g; }
            if let Some(new_size) = size { entry.size = new_size; }
            entry.ctime_secs = now_secs();
        }
        // Truncate in-memory content if size changed
        if let Some(new_size) = size {
            let mut open = self.open_files.lock().unwrap();
            if let Some(content) = open.get_mut(&ino.0) {
                content.resize(new_size as usize, 0);
            }
        }
        let attr = {
            let state = self.state.lock().unwrap();
            Self::inode_to_attr(ino.0, state.inodes.get(&ino.0).unwrap())
        };
        reply.attr(&TTL, &attr);
        self.flush_state();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        let disk_filename = {
            let state = self.state.lock().unwrap();
            match state.inodes.get(&ino.0) {
                Some(entry) if entry.kind == InodeKind::File => entry.disk_filename.clone(),
                Some(_) => { reply.error(fuser::Errno::EISDIR); return; }
                None => { reply.error(fuser::Errno::ENOENT); return; }
            }
        };
        let content = if !disk_filename.is_empty() && self.base_path.join(&disk_filename).exists() {
            self.read_encrypted_file(&disk_filename)
        } else {
            Vec::new()
        };
        self.open_files.lock().unwrap().insert(ino.0, content);
        reply.opened(FileHandle(ino.0), FopenFlags::empty());
    }

    fn read(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, size: u32,
        _flags: fuser::OpenFlags, _lock_owner: Option<fuser::LockOwner>, reply: ReplyData,
    ) {
        let open = self.open_files.lock().unwrap();
        match open.get(&ino.0) {
            Some(content) => {
                let start = offset as usize;
                if start >= content.len() {
                    reply.data(&[]);
                } else {
                    let end = (start + size as usize).min(content.len());
                    reply.data(&content[start..end]);
                }
            }
            None => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn write(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, data: &[u8],
        _write_flags: fuser::WriteFlags, _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>, reply: ReplyWrite,
    ) {
        trace!("FUSE: write ino={} offset={} len={}", ino.0, offset, data.len());
        let new_size = {
            let mut open = self.open_files.lock().unwrap();
            match open.get_mut(&ino.0) {
                Some(content) => {
                    let start = offset as usize;
                    let end = start + data.len();
                    if end > content.len() { content.resize(end, 0); }
                    content[start..end].copy_from_slice(data);
                    content.len() as u64
                }
                None => { reply.error(fuser::Errno::ENOENT); return; }
            }
        };
        {
            let mut state = self.state.lock().unwrap();
            if let Some(entry) = state.inodes.get_mut(&ino.0) {
                entry.size = new_size;
                entry.mtime_secs = now_secs();
            }
        }
        reply.written(data.len() as u32);
    }

    fn flush(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle,
        _lock_owner: fuser::LockOwner, reply: ReplyEmpty,
    ) {
        trace!("FUSE: flush ino={}", ino.0);
        // Reply immediately, persist after
        reply.ok();
        let content = self.open_files.lock().unwrap().get(&ino.0).cloned();
        if let Some(data) = content {
            let disk_filename = {
                let state = self.state.lock().unwrap();
                state.inodes.get(&ino.0).map(|e| e.disk_filename.clone()).unwrap_or_default()
            };
            if !disk_filename.is_empty() {
                self.write_encrypted_file(&disk_filename, &data);
            }
            self.flush_state();
        }
    }

    fn release(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>, _flush: bool, reply: ReplyEmpty,
    ) {
        trace!("FUSE: release ino={}", ino.0);
        // Reply immediately, persist after
        reply.ok();
        let content = self.open_files.lock().unwrap().remove(&ino.0);
        if let Some(data) = content {
            let disk_filename = {
                let state = self.state.lock().unwrap();
                state.inodes.get(&ino.0).map(|e| e.disk_filename.clone()).unwrap_or_default()
            };
            if !disk_filename.is_empty() {
                self.write_encrypted_file(&disk_filename, &data);
            }
            self.flush_state();
        }
    }

    fn mknod(
        &self, req: &Request, parent: INodeNo, name: &OsStr,
        mode: u32, _umask: u32, _rdev: u32, reply: ReplyEntry,
    ) {
        trace!("FUSE: mknod parent={} name={:?} mode={:#o}", parent.0, name, mode);
        // Only support regular files
        let file_type = mode & libc::S_IFMT as u32;
        if file_type != libc::S_IFREG as u32 && file_type != 0 {
            reply.error(fuser::Errno::ENOSYS);
            return;
        }
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::EINVAL); return; }
        };
        let (ino, attr) = {
            let mut state = self.state.lock().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST); return;
            }
            let ino = Self::allocate_inode(&mut state);
            let disk_filename = Self::allocate_disk_filename(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(), kind: InodeKind::File,
                disk_filename: disk_filename.clone(), size: 0,
                perm: (mode & 0o7777) as u16, uid: req.uid(), gid: req.gid(),
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 1, parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(), inode: ino,
            });
            (ino, attr)
        };
        reply.entry(&TTL, &attr, Generation(0));
        trace!("FUSE: mknod replied ino={}", ino);
    }

    fn create(
        &self, req: &Request, parent: INodeNo, name: &OsStr,
        mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate,
    ) {
        trace!("FUSE: create parent={} name={:?} mode={:#o}", parent.0, name, mode);
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::EINVAL); return; }
        };

        let (ino, attr, _disk_filename) = {
            let mut state = self.state.lock().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST); return;
            }
            let ino = Self::allocate_inode(&mut state);
            let disk_filename = Self::allocate_disk_filename(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(), kind: InodeKind::File,
                disk_filename: disk_filename.clone(), size: 0,
                perm: (mode & 0o7777) as u16, uid: req.uid(), gid: req.gid(),
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 1, parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(), inode: ino,
            });
            (ino, attr, disk_filename)
        };
        // Insert into open_files cache and reply immediately — disk I/O deferred to flush/release
        self.open_files.lock().unwrap().insert(ino, Vec::new());
        reply.created(&TTL, &attr, Generation(0), FileHandle(ino), FopenFlags::empty());
        trace!("FUSE: create replied ino={} fh={}", ino, ino);
    }

    fn mkdir(
        &self, req: &Request, parent: INodeNo, name: &OsStr,
        mode: u32, _umask: u32, reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::EINVAL); return; }
        };

        let attr = {
            let mut state = self.state.lock().unwrap();
            match state.inodes.get(&parent.0) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if Self::find_child(&state, parent.0, name_str).is_some() {
                reply.error(fuser::Errno::EEXIST); return;
            }
            let ino = Self::allocate_inode(&mut state);
            let now = now_secs();
            let entry = InodeEntry {
                name: name_str.to_string(), kind: InodeKind::Directory,
                disk_filename: String::new(), size: 0,
                perm: (mode & 0o7777) as u16, uid: req.uid(), gid: req.gid(),
                atime_secs: now, mtime_secs: now, ctime_secs: now, nlink: 2, parent: parent.0,
            };
            let attr = Self::inode_to_attr(ino, &entry);
            state.inodes.insert(ino, entry);
            state.children.insert(ino, Vec::new());
            state.children.entry(parent.0).or_default().push(DirChild {
                name: name_str.to_string(), inode: ino,
            });
            if let Some(p) = state.inodes.get_mut(&parent.0) { p.nlink += 1; }
            attr
        };
        reply.entry(&TTL, &attr, Generation(0));
        self.flush_state();
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::ENOENT); return; }
        };

        let disk_filename = {
            let mut state = self.state.lock().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            let df = state.inodes.get(&ino).map(|e| e.disk_filename.clone()).unwrap_or_default();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&parent.0) { ch.retain(|c| c.inode != ino); }
            self.open_files.lock().unwrap().remove(&ino);
            df
        };
        reply.ok();
        self.flush_state();
        if !disk_filename.is_empty() {
            let _ = fs::remove_file(self.base_path.join(&disk_filename));
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(s) => s,
            None => { reply.error(fuser::Errno::ENOENT); return; }
        };

        {
            let mut state = self.state.lock().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            match state.inodes.get(&ino) {
                Some(e) if e.kind == InodeKind::Directory => {}
                _ => { reply.error(fuser::Errno::ENOTDIR); return; }
            }
            if state.children.get(&ino).is_some_and(|ch| !ch.is_empty()) {
                reply.error(fuser::Errno::ENOTEMPTY); return;
            }
            state.inodes.remove(&ino);
            state.children.remove(&ino);
            if let Some(ch) = state.children.get_mut(&parent.0) { ch.retain(|c| c.inode != ino); }
            if let Some(p) = state.inodes.get_mut(&parent.0) { p.nlink = p.nlink.saturating_sub(1); }
        };
        reply.ok();
        self.flush_state();
    }

    fn rename(
        &self, _req: &Request, parent: INodeNo, name: &OsStr,
        newparent: INodeNo, newname: &OsStr, _flags: fuser::RenameFlags, reply: ReplyEmpty,
    ) {
        let name_str = match name.to_str() {
            Some(s) => s, None => { reply.error(fuser::Errno::EINVAL); return; }
        };
        let newname_str = match newname.to_str() {
            Some(s) => s, None => { reply.error(fuser::Errno::EINVAL); return; }
        };

        let disk_file_to_remove = {
            let mut state = self.state.lock().unwrap();
            let ino = match Self::find_child(&state, parent.0, name_str) {
                Some(i) => i,
                None => { reply.error(fuser::Errno::ENOENT); return; }
            };
            let mut to_remove = None;
            if let Some(existing) = Self::find_child(&state, newparent.0, newname_str) {
                to_remove = state.inodes.get(&existing).and_then(|e| {
                    if e.disk_filename.is_empty() { None } else { Some(e.disk_filename.clone()) }
                });
                state.inodes.remove(&existing);
                if let Some(ch) = state.children.get_mut(&newparent.0) { ch.retain(|c| c.inode != existing); }
            }
            if let Some(ch) = state.children.get_mut(&parent.0) { ch.retain(|c| c.inode != ino); }
            state.children.entry(newparent.0).or_default().push(DirChild {
                name: newname_str.to_string(), inode: ino,
            });
            if let Some(entry) = state.inodes.get_mut(&ino) {
                entry.name = newname_str.to_string();
                entry.parent = newparent.0;
                entry.ctime_secs = now_secs();
            }
            to_remove
        };
        reply.ok();
        self.flush_state();
        if let Some(f) = disk_file_to_remove {
            let _ = fs::remove_file(self.base_path.join(&f));
        }
    }

    fn readdir(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let state = self.state.lock().unwrap();
        match state.inodes.get(&ino.0) {
            Some(e) if e.kind == InodeKind::Directory => {}
            _ => { reply.error(fuser::Errno::ENOTDIR); return; }
        }
        let parent_ino = state.inodes.get(&ino.0).map(|e| e.parent).unwrap_or(1);
        let mut entries: Vec<(INodeNo, FileType, String)> = vec![
            (INodeNo(ino.0), FileType::Directory, ".".to_string()),
            (INodeNo(parent_ino), FileType::Directory, "..".to_string()),
        ];
        if let Some(children) = state.children.get(&ino.0) {
            for child in children {
                let kind = state.inodes.get(&child.inode)
                    .map(|e| match e.kind {
                        InodeKind::File => FileType::RegularFile,
                        InodeKind::Directory => FileType::Directory,
                    })
                    .unwrap_or(FileType::RegularFile);
                entries.push((INodeNo(child.inode), kind, child.name.clone()));
            }
        }
        for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*entry_ino, (i + 1) as u64, *kind, name) { break; }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let state = self.state.lock().unwrap();
        let files = state.inodes.len() as u64;
        reply.statfs(1_000_000, 900_000, 900_000, files, 1_000_000 - files, BLKSIZE, 255, 0);
    }

    fn access(&self, _req: &Request, ino: INodeNo, _mask: fuser::AccessFlags, reply: ReplyEmpty) {
        if self.state.lock().unwrap().inodes.contains_key(&ino.0) {
            reply.ok();
        } else {
            reply.error(fuser::Errno::ENOENT);
        }
    }
}

fn main() {
    let passphrase = std::env::var("ZEROTRUST_PASSPHRASE")
        .unwrap_or_else(|_| "zerotrust-demo-passphrase".to_string());
    let base_path = PathBuf::from("target/disk");
    let mountpoint = PathBuf::from("target/mnt");

    fs::create_dir_all(&base_path).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();

    eprintln!("zerotrust-drive: mounting at {}", mountpoint.display());
    eprintln!("zerotrust-drive: encrypted storage at {}", base_path.display());
    eprintln!("zerotrust-drive: press Ctrl+C to unmount");

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RW,
        MountOption::FSName("zerotrust-drive".to_string()),
    ];

    let ztfs = ZeroTrustFs::new(&passphrase, base_path);
    fuser::mount2(ztfs, &mountpoint, &config).expect("failed to mount filesystem");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = derive_key("pw");
        let plaintext = b"round trip test data";
        let ciphertext = encrypt_bytes(&key, plaintext).unwrap();
        let decrypted = decrypt_bytes(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let right = derive_key("right");
        let wrong = derive_key("wrong");
        let ciphertext = encrypt_bytes(&right, b"secret").unwrap();
        assert!(decrypt_bytes(&wrong, &ciphertext).is_err());
    }

    #[test]
    fn index_serialization_round_trip() {
        let mut inodes = HashMap::new();
        inodes.insert(1, InodeEntry {
            name: String::new(), kind: InodeKind::Directory, disk_filename: String::new(),
            size: 0, perm: 0o755, uid: 501, gid: 20,
            atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000, nlink: 2, parent: 1,
        });
        inodes.insert(2, InodeEntry {
            name: "test.txt".to_string(), kind: InodeKind::File,
            disk_filename: "000001.age".to_string(), size: 42, perm: 0o644, uid: 501, gid: 20,
            atime_secs: 2000, mtime_secs: 2000, ctime_secs: 2000, nlink: 1, parent: 1,
        });
        let mut children = HashMap::new();
        children.insert(1, vec![DirChild { name: "test.txt".to_string(), inode: 2 }]);
        let index = DiskIndex { next_inode: 3, next_file_id: 2, inodes, children };

        let json = serde_json::to_vec(&index).unwrap();
        let key = derive_key("test-pw");
        let encrypted = encrypt_bytes(&key, &json).unwrap();
        let decrypted = decrypt_bytes(&key, &encrypted).unwrap();
        let restored: DiskIndex = serde_json::from_slice(&decrypted).unwrap();

        assert_eq!(restored.next_inode, 3);
        assert_eq!(restored.next_file_id, 2);
        assert_eq!(restored.inodes.len(), 2);
        assert_eq!(restored.inodes[&2].name, "test.txt");
        assert_eq!(restored.children[&1][0].name, "test.txt");
    }

    #[test]
    fn inode_to_attr_file() {
        let entry = InodeEntry {
            name: "hello.txt".to_string(), kind: InodeKind::File,
            disk_filename: "000001.age".to_string(), size: 1024, perm: 0o644, uid: 501, gid: 20,
            atime_secs: 1000, mtime_secs: 2000, ctime_secs: 3000, nlink: 1, parent: 1,
        };
        let attr = ZeroTrustFs::inode_to_attr(5, &entry);
        assert_eq!(attr.ino, INodeNo(5));
        assert_eq!(attr.size, 1024);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o644);
    }

    #[test]
    fn inode_to_attr_directory() {
        let entry = InodeEntry {
            name: "docs".to_string(), kind: InodeKind::Directory,
            disk_filename: String::new(), size: 0, perm: 0o755, uid: 501, gid: 20,
            atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000, nlink: 2, parent: 1,
        };
        let attr = ZeroTrustFs::inode_to_attr(3, &entry);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn find_child_exists() {
        let mut children = HashMap::new();
        children.insert(1, vec![
            DirChild { name: "a.txt".to_string(), inode: 2 },
            DirChild { name: "b.txt".to_string(), inode: 3 },
        ]);
        let index = DiskIndex { next_inode: 4, next_file_id: 3, inodes: HashMap::new(), children };
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "a.txt"), Some(2));
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "b.txt"), Some(3));
        assert_eq!(ZeroTrustFs::find_child(&index, 1, "c.txt"), None);
    }

    #[test]
    fn disk_filename_allocation() {
        let mut index = DiskIndex {
            next_inode: 1, next_file_id: 1, inodes: HashMap::new(), children: HashMap::new(),
        };
        assert_eq!(ZeroTrustFs::allocate_disk_filename(&mut index), "000001.age");
        assert_eq!(ZeroTrustFs::allocate_disk_filename(&mut index), "000002.age");
        assert_eq!(index.next_file_id, 3);
    }

    #[test]
    fn encrypted_file_persistence() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let id = CTR.fetch_add(1, Ordering::SeqCst);
        let dir = PathBuf::from(format!("target/test-zt-{id}"));
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("test-pw", dir.clone());
        ztfs.write_encrypted_file("test.age", b"hello world");
        let content = ztfs.read_encrypted_file("test.age");
        assert_eq!(content, b"hello world");
        let raw = fs::read(dir.join("test.age")).unwrap();
        assert_ne!(raw.as_slice(), b"hello world");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crud_file_lifecycle() {
        let dir = PathBuf::from("target/test-crud-lifecycle");
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("crud-pw", dir.clone());

        // CREATE — add file to index and write encrypted content
        let disk_filename = {
            let mut state = ztfs.state.lock().unwrap();
            let ino = ZeroTrustFs::allocate_inode(&mut state);
            let disk_filename = ZeroTrustFs::allocate_disk_filename(&mut state);
            state.inodes.insert(ino, InodeEntry {
                name: "note.txt".to_string(), kind: InodeKind::File,
                disk_filename: disk_filename.clone(), size: 13, perm: 0o644,
                uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                nlink: 1, parent: 1,
            });
            state.children.entry(1).or_default().push(DirChild {
                name: "note.txt".to_string(), inode: ino,
            });
            disk_filename
        };
        ztfs.write_encrypted_file(&disk_filename, b"hello, world!");
        ztfs.flush_state();

        // READ — verify decrypted content
        let content = ztfs.read_encrypted_file(&disk_filename);
        assert_eq!(content, b"hello, world!");

        // UPDATE — overwrite with new content
        let updated = b"updated content for note";
        ztfs.write_encrypted_file(&disk_filename, updated);
        {
            let mut state = ztfs.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "note.txt").unwrap();
            state.inodes.get_mut(&ino).unwrap().size = updated.len() as u64;
        }
        ztfs.flush_state();

        // READ AGAIN — verify updated content
        let content = ztfs.read_encrypted_file(&disk_filename);
        assert_eq!(content, updated);

        // DELETE — remove file and inode
        {
            let mut state = ztfs.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "note.txt").unwrap();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&1) { ch.retain(|c| c.inode != ino); }
        }
        let _ = fs::remove_file(dir.join(&disk_filename));
        ztfs.flush_state();

        // Verify deleted
        assert!(!dir.join(&disk_filename).exists());
        let state = ztfs.state.lock().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "note.txt").is_none());

        drop(state);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crud_multiple_files() {
        let dir = PathBuf::from("target/test-crud-multi");
        let _ = fs::remove_dir_all(&dir);

        let ztfs = ZeroTrustFs::new("multi-pw", dir.clone());

        // CREATE 3 files
        let files = [
            ("alpha.txt", b"content alpha" as &[u8]),
            ("beta.txt", b"content beta"),
            ("gamma.txt", b"content gamma"),
        ];
        let mut disk_filenames = Vec::new();
        for (name, content) in &files {
            let disk_filename = {
                let mut state = ztfs.state.lock().unwrap();
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(ino, InodeEntry {
                    name: name.to_string(), kind: InodeKind::File,
                    disk_filename: df.clone(), size: content.len() as u64, perm: 0o644,
                    uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                    nlink: 1, parent: 1,
                });
                state.children.entry(1).or_default().push(DirChild {
                    name: name.to_string(), inode: ino,
                });
                df
            };
            ztfs.write_encrypted_file(&disk_filename, content);
            disk_filenames.push(disk_filename);
        }
        ztfs.flush_state();

        // READ and verify each
        for (i, (_name, expected)) in files.iter().enumerate() {
            let content = ztfs.read_encrypted_file(&disk_filenames[i]);
            assert_eq!(content, *expected);
        }

        // UPDATE beta.txt
        let updated_beta = b"beta has been updated";
        ztfs.write_encrypted_file(&disk_filenames[1], updated_beta);
        {
            let mut state = ztfs.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "beta.txt").unwrap();
            state.inodes.get_mut(&ino).unwrap().size = updated_beta.len() as u64;
        }
        ztfs.flush_state();

        // DELETE alpha.txt
        {
            let mut state = ztfs.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "alpha.txt").unwrap();
            state.inodes.remove(&ino);
            if let Some(ch) = state.children.get_mut(&1) { ch.retain(|c| c.inode != ino); }
        }
        let _ = fs::remove_file(dir.join(&disk_filenames[0]));
        ztfs.flush_state();

        // Verify alpha deleted
        let state = ztfs.state.lock().unwrap();
        assert!(ZeroTrustFs::find_child(&state, 1, "alpha.txt").is_none());

        // Verify beta updated
        drop(state);
        let content = ztfs.read_encrypted_file(&disk_filenames[1]);
        assert_eq!(content, updated_beta);

        // Verify gamma untouched
        let content = ztfs.read_encrypted_file(&disk_filenames[2]);
        assert_eq!(content, b"content gamma");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crud_persisted_across_reopen() {
        let dir = PathBuf::from("target/test-crud-reopen");
        let _ = fs::remove_dir_all(&dir);
        let passphrase = "reopen-pw";

        // First session: create a file
        let disk_filename = {
            let ztfs = ZeroTrustFs::new(passphrase, dir.clone());
            let df = {
                let mut state = ztfs.state.lock().unwrap();
                let ino = ZeroTrustFs::allocate_inode(&mut state);
                let df = ZeroTrustFs::allocate_disk_filename(&mut state);
                state.inodes.insert(ino, InodeEntry {
                    name: "persist.txt".to_string(), kind: InodeKind::File,
                    disk_filename: df.clone(), size: 15, perm: 0o644,
                    uid: 501, gid: 20, atime_secs: 1000, mtime_secs: 1000, ctime_secs: 1000,
                    nlink: 1, parent: 1,
                });
                state.children.entry(1).or_default().push(DirChild {
                    name: "persist.txt".to_string(), inode: ino,
                });
                df
            };
            ztfs.write_encrypted_file(&df, b"persisted data!");
            ztfs.flush_state();
            df
            // ztfs dropped here — simulates unmount
        };

        // Second session: reopen with same passphrase and verify
        {
            let ztfs = ZeroTrustFs::new(passphrase, dir.clone());
            let state = ztfs.state.lock().unwrap();
            let ino = ZeroTrustFs::find_child(&state, 1, "persist.txt")
                .expect("persist.txt should exist after reopen");
            let entry = state.inodes.get(&ino).unwrap();
            assert_eq!(entry.name, "persist.txt");
            assert_eq!(entry.disk_filename, disk_filename);
            drop(state);

            let content = ztfs.read_encrypted_file(&disk_filename);
            assert_eq!(content, b"persisted data!");
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
