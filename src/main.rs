mod lang;
mod win;

use memchr::memmem;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use winreg::enums::*;
use winreg::RegKey;

use lang::Lang;
static LANG: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const ALL_LANGS: [Lang; 10] = [Lang::En, Lang::Ru, Lang::Uk, Lang::De, Lang::Es, Lang::Fr, Lang::Pt, Lang::Pl, Lang::Tr, Lang::Zh];
fn cur_lang() -> Lang {
    ALL_LANGS[LANG.load(Ordering::Relaxed) as usize]
}
fn set_lang(l: Lang) {
    let i = ALL_LANGS.iter().position(|x| *x == l).unwrap_or(0);
    LANG.store(i as u8, Ordering::Relaxed);
}
fn trf(ru: &str, en: &str, args: &[String]) -> String {
    let tpl = match cur_lang() {
        Lang::Ru => ru,
        Lang::En => en,
        l => lang::lookup(l, en).unwrap_or(en),
    };
    let mut out = String::with_capacity(tpl.len() + 16);
    let mut it = args.iter();
    let mut rest = tpl;
    while let Some(i) = rest.find("{}") {
        out.push_str(&rest[..i]);
        if let Some(a) = it.next() {
            out.push_str(a);
        }
        rest = &rest[i + 2..];
    }
    out.push_str(rest);
    out
}
macro_rules! tr {
    ($ru:literal, $en:literal $(, $a:expr)* $(,)?) => {
        trf($ru, $en, &[$(format!("{}", $a)),*])
    };
}

const MAX_READ: u64 = 80 * 1024 * 1024;
const R: &str = "\x1b[0m";
const RED: &str = "\x1b[91m";
const YEL: &str = "\x1b[93m";
const GRN: &str = "\x1b[92m";
const CYN: &str = "\x1b[96m";
const DIM: &str = "\x1b[90m";

// сигнатуры (задом наперёд)
fn rev(s: &str) -> String {
    s.chars().rev().collect()
}
fn miner_strings() -> Vec<Vec<u8>> {
    [
        "//:pct+mutarts", "//:lss+mutarts", "level-etanod--", "thgirotpyc", "xmodnar", "girmx",
        "renimupc", "hsahecin", "etarhsah", "rmxenim", "gro.oloponan", "ommxtroppus",
        "ahcoonaromi", "moc.srenim2", "remehte", "wprak", "hsahte",
    ]
    .iter()
    .map(|s| rev(s).into_bytes())
    .collect()
}
fn miner_names() -> Vec<String> {
    [
        "girmx", "renimbn", "xert", "renimxinehp", "renimlol", "renimg", "renimhte", "renimupc",
        "dnerim", "renimbrs", "renimonan", "renimmaetder", "ahcsnu", "renimzb", "dlirwiw",
        "karts-rmx", "hsahecin", "ptyrk", "etagrenim", "renimgc", "renimfgb", "renimcc",
    ]
    .iter()
    .map(|s| rev(s))
    .collect()
}
fn miner_cmd() -> Vec<String> {
    ["mutarts", "level-etanod--", "ytiroirp-upc--", "ogla--"]
        .iter()
        .map(|s| rev(s))
        .collect()
}

#[derive(Default, Clone)]
struct HotInfo {
    sources: Vec<String>,
    pids: Vec<u32>,
    cmds: Vec<String>,
    cpu: f32,
    autostart: bool,
    regs: Vec<(bool, String, String)>,
    pool: Vec<String>,
}

struct Analysis {
    path: PathBuf,
    score: i32,
    reasons: Vec<String>,
    sha: String,
    hot: Option<HotInfo>,
    info: (String, String, String),
    online: Vec<String>,
}

fn windir() -> String {
    std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase()
}

fn trusted_path(lp: &str, wd: &str) -> bool {
    if lp.starts_with(wd) {
        let rest = &lp[wd.len()..];
        return !(rest.starts_with("\\temp") || rest.starts_with("\\tasks"));
    }
    lp.contains("\\windowsapps\\")
}

fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        if let Some(j) = after.find('%') {
            let name = &after[..j];
            match std::env::var(name) {
                Ok(v) => out.push_str(&v),
                Err(_) => {
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[j + 1..];
        } else {
            out.push('%');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn extract_exe(cmd: &str) -> Option<PathBuf> {
    let c = expand_env(cmd.trim());
    let c = c.trim_start_matches("\\??\\").to_string();
    let raw: String = if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        let l = c.to_ascii_lowercase();
        let mut cut = None;
        for ext in [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com"] {
            if let Some(i) = l.find(ext) {
                let e = i + ext.len();
                if cut.map_or(true, |x| e < x) {
                    cut = Some(e);
                }
            }
        }
        match cut {
            Some(e) => c[..e].to_string(),
            None => c.split_whitespace().next()?.to_string(),
        }
    };
    let p = PathBuf::from(raw.trim());
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

fn add_hot(map: &mut HashMap<String, (PathBuf, HotInfo)>, p: PathBuf, f: impl FnOnce(&mut HotInfo)) {
    let key = p.to_string_lossy().to_lowercase();
    let e = map.entry(key).or_insert_with(|| (p, HotInfo::default()));
    f(&mut e.1);
}

fn collect_hot(sys: &mut System) -> (HashMap<String, (PathBuf, HotInfo)>, Vec<String>) {
    let mut notes: Vec<String> = vec![];
    let mut map: HashMap<String, (PathBuf, HotInfo)> = HashMap::new();
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f32;

    // процессы
    let kind = ProcessRefreshKind::everything();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    std::thread::sleep(Duration::from_millis(1200));
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    for (pid, p) in sys.processes() {
        if let Some(exe) = p.exe() {
            let cmd = p.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" ");
            let cpu = p.cpu_usage() / ncpu;
            let pid = pid.as_u32();
            add_hot(&mut map, exe.to_path_buf(), |h| {
                let run = tr!("запущен", "running");
                if !h.sources.iter().any(|s| *s == run) {
                    h.sources.push(run);
                }
                h.pids.push(pid);
                h.cmds.push(cmd);
                if cpu > h.cpu {
                    h.cpu = cpu;
                }
            });
        }
    }

    // сеть: майнинг-пулы
    let pool_ports: [u16; 13] = [3333, 4444, 5555, 6633, 7777, 9999, 10128, 13333, 14433, 14444, 3357, 5730, 45700];
    let mut pid_exe: HashMap<u32, PathBuf> = HashMap::new();
    for (pid, p) in sys.processes() {
        if let Some(e) = p.exe() {
            pid_exe.insert(pid.as_u32(), e.to_path_buf());
        }
    }
    for (pid, addr, port) in win::tcp_conns() {
        if pool_ports.contains(&port) {
            if let Some(exe) = pid_exe.get(&pid) {
                add_hot(&mut map, exe.clone(), |h| h.pool.push(addr));
            }
        }
    }

    // автозапуск: реестр
    let runs = ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"];
    for (hklm, root) in [(false, RegKey::predef(HKEY_CURRENT_USER)), (true, RegKey::predef(HKEY_LOCAL_MACHINE))] {
        let mut subs: Vec<String> = runs.iter().map(|s| s.to_string()).collect();
        if hklm {
            subs.push("Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".into());
        }
        for sub in subs {
            if let Ok(k) = root.open_subkey(&sub) {
                for (name, _) in k.enum_values().flatten() {
                    if let Ok(v) = k.get_value::<String, _>(&name) {
                        let lv = v.to_lowercase();
                        if ["-enc", "-encodedcommand", "downloadstring", "frombase64string", "iex(", "iex "].iter().any(|x| lv.contains(x)) {
                            notes.push(tr!("автозапуск «{}» запускает скрытый/закодированный PowerShell: {}", "autostart entry \"{}\" runs hidden/encoded PowerShell: {}", name, v.chars().take(120).collect::<String>()));
                        }
                        if let Some(p) = extract_exe(&v) {
                            let (sub, name) = (sub.clone(), name.clone());
                            add_hot(&mut map, p, |h| {
                                h.autostart = true;
                                h.sources.push(tr!("автозапуск (реестр: {})", "autostart (registry: {})", name));
                                h.cmds.push(v.clone());
                                h.regs.push((hklm, sub, name));
                            });
                        }
                    }
                }
            }
        }
    }

    // автозапуск: папки Startup
    let mut startup = vec![];
    if let Ok(a) = std::env::var("APPDATA") {
        startup.push(PathBuf::from(a).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(a) = std::env::var("PROGRAMDATA") {
        startup.push(PathBuf::from(a).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    for d in startup {
        if let Ok(rd) = fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                let ext = p.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
                if matches!(ext.as_str(), "exe" | "bat" | "cmd" | "vbs" | "ps1" | "scr") {
                    add_hot(&mut map, p, |h| {
                        h.autostart = true;
                        h.sources.push(tr!("автозапуск (папка Startup)", "autostart (Startup folder)"));
                    });
                }
            }
        }
    }

    // планировщик задач
    let tasks = PathBuf::from(std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\Tasks");
    for e in walkdir::WalkDir::new(&tasks)
        .into_iter()
        .filter_entry(|e| !e.file_name().to_string_lossy().eq_ignore_ascii_case("microsoft"))
        .flatten()
    {
        if !e.file_type().is_file() {
            continue;
        }
        let Ok(bytes) = fs::read(e.path()) else { continue };
        let text = if bytes.starts_with(&[0xFF, 0xFE]) {
            let u: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u)
        } else {
            String::from_utf8_lossy(&bytes).to_string()
        };
        let mut rest = text.as_str();
        while let Some(i) = rest.find("<Command>") {
            let after = &rest[i + 9..];
            let Some(j) = after.find("</Command>") else { break };
            if let Some(p) = extract_exe(&after[..j]) {
                let name = e.file_name().to_string_lossy().to_string();
                add_hot(&mut map, p, |h| {
                    h.autostart = true;
                    h.sources.push(tr!("задача планировщика: {}", "scheduled task: {}", name));
                });
            }
            rest = &after[j..];
        }
    }

    // службы
    if let Ok(svcs) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SYSTEM\\CurrentControlSet\\Services") {
        for n in svcs.enum_keys().flatten() {
            if let Ok(k) = svcs.open_subkey(&n) {
                if let Ok(v) = k.get_value::<String, _>("ImagePath") {
                    if let Some(p) = extract_exe(&v) {
                        add_hot(&mut map, p, |h| {
                            h.autostart = true;
                            h.sources.push(tr!("служба: {}", "service: {}", n));
                        });
                    }
                }
            }
        }
    }
    // Defender и IFEO
    if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths") {
        for (name, _) in k.enum_values().flatten() {
            notes.push(tr!("исключение Defender: {} (майнеры любят прятаться в таких папках)", "Defender exclusion: {} (miners often hide in excluded folders)", name));
        }
    }
    if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options") {
        for n in k.enum_keys().flatten() {
            if let Ok(sk) = k.open_subkey(&n) {
                if let Ok(d) = sk.get_value::<String, _>("Debugger") {
                    notes.push(tr!("подмена запуска {} → {} (IFEO)", "launch hijack {} → {} (IFEO)", n, d));
                }
            }
        }
    }
    (map, notes)
}

fn scan_roots(full: bool) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = vec![];
    if full {
        for d in win::fixed_drives() {
            v.push(PathBuf::from(d));
        }
        v.push(PathBuf::from(windir()).join("Temp"));
        return v;
    }
    let env = |k: &str| std::env::var(k).ok().map(PathBuf::from);
    for k in ["TEMP", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA"] {
        if let Some(p) = env(k) {
            v.push(p);
        }
    }
    v.push(PathBuf::from("C:\\Users\\Public"));
    v.push(PathBuf::from(windir()).join("Temp"));
    if let Some(u) = env("USERPROFILE") {
        for d in ["Downloads", "Desktop", "Documents"] {
            v.push(u.join(d));
        }
    }
    v
}

fn collect_files(roots: &[PathBuf], wd: &str, full: bool) -> Vec<PathBuf> {
    let skip_dirs: HashSet<&str> = [
        "node_modules", "cache", "code cache", "gpucache", "service worker", ".git", "__pycache__",
        "winsxs", "windowsapps", "servicing", "user data",
    ]
    .into_iter()
    .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = vec![];
    for r in roots {
        let w = walkdir::WalkDir::new(r).follow_links(false).into_iter().filter_entry(|e| {
            if e.file_type().is_dir() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if skip_dirs.contains(n.as_str()) {
                    return false;
                }
                if full {
                    let lp = e.path().to_string_lossy().to_lowercase();
                    if lp == wd {
                        return false;
                    }
                }
            }
            true
        });
        for e in w.flatten() {
            if !e.file_type().is_file() {
                continue;
            }
            let ext = e.path().extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
            if matches!(ext.as_str(), "exe" | "dll" | "scr" | "com" | "cpl" | "bat" | "cmd" | "ps1" | "vbs") {
                let key = e.path().to_string_lossy().to_lowercase();
                if seen.insert(key) {
                    out.push(e.into_path());
                }
            }
        }
    }
    out
}

fn entropy(buf: &[u8]) -> f64 {
    let mut c = [0u64; 256];
    for &b in buf {
        c[b as usize] += 1;
    }
    let n = buf.len() as f64;
    c.iter().filter(|&&x| x > 0).map(|&x| {
        let p = x as f64 / n;
        -p * p.log2()
    }).sum()
}

const MALWARE_WORDS: [&str; 9] = ["trojan", "keylogger", "stealer", "ransom", "backdoor", "malware", "cryptolocker", "botnet", "rootkit"];

fn analyze(
    path: &Path,
    hot: Option<&HotInfo>,
    pats: &[Vec<u8>],
    names: &[String],
    cmds: &[String],
    wd: &str,
    me: &str,
) -> Option<Analysis> {
    let lp = path.to_string_lossy().to_lowercase();
    if lp == me || trusted_path(&lp, wd) {
        return None;
    }
    let len = fs::metadata(path).ok()?.len();
    if len < 2048 {
        return None;
    }
    let ext = path.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
    let pe_ext = matches!(ext.as_str(), "exe" | "dll" | "scr" | "com" | "cpl");

    let mut f = File::open(path).ok()?;
    let mut head = [0u8; 2];
    f.read_exact(&mut head).ok()?;
    let is_pe = &head == b"MZ";
    if is_pe && win::is_signed(path) {
        return None;
    }
    if pe_ext && !is_pe {
        return None;
    }

    let mut score = 0;
    let mut reasons: Vec<String> = vec![];
    let mut sha = String::new();

    if len <= MAX_READ {
        let mut buf = head.to_vec();
        f.take(MAX_READ).read_to_end(&mut buf).ok()?;
        sha = format!("{:x}", Sha256::digest(&buf));
        if is_pe && buf.len() > 65536 && entropy(&buf) > 7.3 {
            score += 1;
            reasons.push(tr!("файл упакован/зашифрован (высокая энтропия)", "file is packed/encrypted (high entropy)"));
        }
        buf.make_ascii_lowercase();
        let n = pats.iter().filter(|p| memmem::find(&buf, p).is_some()).count();
        if n >= 3 {
            score += 8;
            reasons.push(tr!("внутри строки майнера ({} совпадений)", "contains miner strings ({} matches)", n));
        } else if n == 2 {
            score += 4;
            reasons.push(tr!("внутри 2 строки, характерные для майнеров", "contains 2 strings typical of miners"));
        }
    }

    let stem = path.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    if names.iter().any(|n| stem.contains(n.as_str())) {
        score += 4;
        reasons.push(tr!("имя файла как у известного майнера", "file name matches a known miner"));
    }
    let stem_nav = stem.replace("antivirus", "");
    if MALWARE_WORDS.iter().any(|w| stem_nav.contains(w)) || stem_nav.contains("virus") {
        score += 8;
        reasons.push(tr!("в имени файла прямо написано название вредоноса", "file name explicitly contains a malware term"));
    }

    if let Some(h) = hot {
        let cl = h.cmds.join(" ").to_lowercase();
        if cmds.iter().any(|c| cl.contains(c.as_str())) {
            score += 8;
            reasons.push(tr!("командная строка как у майнера (пул/алгоритм)", "miner-like command line (pool/algorithm)"));
        }
        if !h.pool.is_empty() {
            score += 4;
            reasons.push(tr!("держит соединение с портом майнинг-пула ({})", "connected to a mining-pool port ({})", h.pool[0]));
        }
        if h.cpu >= 35.0 {
            score += 2;
            reasons.push(tr!("грузит CPU на {}% всей системы", "uses {}% of total CPU", format!("{:.0}", h.cpu)));
        }
        if h.autostart && (lp.contains("\\temp\\") || lp.contains("\\users\\public\\")) {
            score += 2;
            reasons.push(tr!("автозапуск из временной/общей папки", "autostarts from a temp/public folder"));
        }
    }

    let info = if is_pe { win::version_info(path) } else { Default::default() };
    Some(Analysis { path: path.to_path_buf(), score, reasons, sha, hot: hot.cloned(), info, online: vec![] })
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build()
}

// Касперский OpenTIP
fn kl_lookup(sha: &str, key: &str) -> Option<String> {
    match agent().get("https://opentip.kaspersky.com/api/v1/search/hash").query("request", sha).set("x-api-key", key).call() {
        Ok(r) => {
            let v: serde_json::Value = serde_json::from_reader(r.into_reader()).ok()?;
            v["Zone"].as_str().map(|s| s.to_string())
        }
        Err(ureq::Error::Status(404, _)) => Some("Grey".into()),
        Err(_) => None,
    }
}

// VirusTotal
fn vt_lookup(sha: &str, key: &str) -> Option<(u32, u32, Option<String>)> {
    let r = agent().get(&format!("https://www.virustotal.com/api/v3/files/{}", sha)).set("x-apikey", key).call().ok()?;
    let v: serde_json::Value = serde_json::from_reader(r.into_reader()).ok()?;
    let at = &v["data"]["attributes"];
    let st = &at["last_analysis_stats"];
    let kas = at["last_analysis_results"]["Kaspersky"]["result"].as_str().map(|s| s.to_string());
    Some((st["malicious"].as_u64()? as u32, st["suspicious"].as_u64().unwrap_or(0) as u32, kas))
}

fn key_from(env: &str, file: &str) -> Option<String> {
    if let Ok(k) = std::env::var(env) {
        if !k.trim().is_empty() {
            return Some(k.trim().to_string());
        }
    }
    let p = PathBuf::from(std::env::var("LOCALAPPDATA").ok()?).join("sweep").join(file);
    fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

// онлайн-проверка
fn online_check(res: &mut Vec<Analysis>, kl: Option<&str>, vt: Option<&str>) {
    let mut idxs: Vec<usize> = res.iter().enumerate().filter(|(_, a)| a.score >= 1 && a.score < 8 && !a.sha.is_empty()).map(|(i, _)| i).collect();
    if idxs.is_empty() {
        return;
    }
    if kl.is_none() && vt.is_none() {
        println!("{DIM}{}{R}", tr!("сомнительных файлов: {}, но ключей онлайн-проверки нет (KL_KEY / VT_KEY) — оставляю локальную оценку", "doubtful files: {}, but no online-check keys (KL_KEY / VT_KEY) — keeping local verdict", idxs.len()));
        return;
    }
    idxs.sort_by(|&a, &b| res[b].score.cmp(&res[a].score));
    idxs.truncate(30);
    println!("{}", tr!("Сомнительных файлов: {} → проверяю по хэшу онлайн (сам файл не отправляется)…", "Doubtful files: {} → checking hashes online (files are not uploaded)…", idxs.len()));

    // Касперский
    let mut zones: Vec<Option<String>> = vec![None; idxs.len()];
    if let Some(k) = kl {
        let shas: Vec<String> = idxs.iter().map(|&i| res[i].sha.clone()).collect();
        let next = AtomicUsize::new(0);
        let out: Mutex<Vec<Option<String>>> = Mutex::new(vec![None; shas.len()]);
        std::thread::scope(|sc| {
            for _ in 0..4 {
                sc.spawn(|| loop {
                    let j = next.fetch_add(1, Ordering::Relaxed);
                    if j >= shas.len() {
                        break;
                    }
                    let z = kl_lookup(&shas[j], k);
                    out.lock().unwrap()[j] = z;
                });
            }
        });
        zones = out.into_inner().unwrap();
    }
    let mut vt_queue: Vec<usize> = vec![];
    for (j, &i) in idxs.iter().enumerate() {
        match zones[j].as_deref() {
            Some(z) => {
                res[i].online.push(tr!("Касперский: {}", "Kaspersky: {}", z));
                match z {
                    "Red" => {
                        res[i].score += 8;
                        res[i].reasons.push(tr!("Касперский (OpenTIP): вредоносный", "Kaspersky (OpenTIP): malicious"));
                    }
                    "Green" => res[i].score = res[i].score.min(2),
                    "Yellow" | "Orange" => {
                        res[i].score += 3;
                        res[i].reasons.push(tr!("Касперский (OpenTIP): зона {}", "Kaspersky (OpenTIP): zone {}", z));
                    }
                    _ => {
                        if res[i].score >= 3 {
                            vt_queue.push(i);
                        }
                    }
                }
            }
            None => {
                if res[i].score >= 3 {
                    vt_queue.push(i);
                }
            }
        }
    }

    // VirusTotal
    let Some(k) = vt else { return };
    vt_queue.truncate(8);
    for (n, i) in vt_queue.into_iter().enumerate() {
        if n > 0 && n % 4 == 0 {
            println!("{DIM}{}{R}", tr!("жду минуту — лимит бесплатного VirusTotal…", "waiting a minute — free VirusTotal rate limit…"));
            std::thread::sleep(Duration::from_secs(61));
        }
        let sha = res[i].sha.clone();
        if let Some((m, s, kas)) = vt_lookup(&sha, k) {
            res[i].online.push(tr!("VirusTotal: {} вредоносных, {} подозрительных", "VirusTotal: {} malicious, {} suspicious", m, s));
            if let Some(kn) = kas {
                res[i].online.push(tr!("Касперский (через VT): {}", "Kaspersky (via VT): {}", kn));
                res[i].score += 4;
                res[i].reasons.push(tr!("Касперский (через VT) определяет как {}", "Kaspersky (via VT) detects it as {}", kn));
            }
            if m >= 8 {
                res[i].score += 8;
                res[i].reasons.push(tr!("VirusTotal: {} антивирусов считают вредоносным", "VirusTotal: {} engines flag it as malicious", m));
            } else if m >= 3 {
                res[i].score += 3;
                res[i].reasons.push(tr!("VirusTotal: {} детектов", "VirusTotal: {} detections", m));
            } else if m == 0 && s == 0 {
                res[i].score = res[i].score.saturating_sub(2);
            }
        }
    }
}

fn quarantine(a: &Analysis, sys: &System) -> io::Result<PathBuf> {
    if let Some(h) = &a.hot {
        for pid in &h.pids {
            if let Some(p) = sys.process(Pid::from_u32(*pid)) {
                p.kill();
            }
        }
        for (hklm, sub, name) in &h.regs {
            let root = RegKey::predef(if *hklm { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER });
            if let Ok(k) = root.open_subkey_with_flags(sub, KEY_SET_VALUE) {
                let _ = k.delete_value(name);
            }
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    let dir = PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into())).join("sweep\\quarantine");
    fs::create_dir_all(&dir)?;
    let short = if a.sha.len() >= 16 { &a.sha[..16] } else { "nohash" };
    let dest = dir.join(format!("{}.quar", short));
    if fs::rename(&a.path, &dest).is_err() {
        fs::copy(&a.path, &dest)?;
        fs::remove_file(&a.path)?;
    }
    let mut m = fs::OpenOptions::new().create(true).append(true).open(dir.join("manifest.txt"))?;
    writeln!(m, "{}\t{}", dest.display(), a.path.display())?;
    Ok(dest)
}

fn sweep_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into())).join("sweep")
}

// белый список
fn load_allow() -> Vec<String> {
    fs::read_to_string(sweep_dir().join("allow.txt"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().trim_matches('"').to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn add_allow(path: &str) {
    let full = fs::canonicalize(path).map(|p| p.to_string_lossy().trim_start_matches("\\\\?\\").to_string()).unwrap_or_else(|_| path.to_string());
    let _ = fs::create_dir_all(sweep_dir());
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(sweep_dir().join("allow.txt")) {
        let _ = writeln!(f, "{}", full);
        println!("{GRN}{}{R}", tr!("Добавлено в белый список: {}", "Added to allowlist: {}", full));
    }
}

fn restore_all() {
    let dir = sweep_dir().join("quarantine");
    let manifest = dir.join("manifest.txt");
    let text = fs::read_to_string(&manifest).unwrap_or_default();
    let mut left = String::new();
    let mut n = 0;
    for line in text.lines() {
        let Some((q, orig)) = line.split_once('\t') else { continue };
        let (q, orig) = (PathBuf::from(q), PathBuf::from(orig));
        if !q.exists() {
            continue;
        }
        if let Some(parent) = orig.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let ok = fs::rename(&q, &orig).is_ok() || (fs::copy(&q, &orig).is_ok() && fs::remove_file(&q).is_ok());
        if ok {
            n += 1;
            println!("{GRN}{} → {}{R}", tr!("восстановлен", "restored"), orig.display());
        } else {
            left.push_str(line);
            left.push('\n');
            println!("{RED}{}: {}{R}", tr!("не вышло", "failed"), orig.display());
        }
    }
    let _ = fs::write(&manifest, left);
    println!("{}", tr!("Восстановлено файлов: {}", "Files restored: {}", n));
}

fn list_quarantine() {
    let text = fs::read_to_string(sweep_dir().join("quarantine").join("manifest.txt")).unwrap_or_default();
    let items: Vec<&str> = text.lines().filter(|l| l.contains('\t')).collect();
    if items.is_empty() {
        println!("{}", tr!("Карантин пуст.", "Quarantine is empty."));
    }
    for l in items {
        if let Some((_, orig)) = l.split_once('\t') {
            println!("  {}", orig);
        }
    }
}

fn print_help() {
    println!("{CYN}sweep{R} {}", env!("CARGO_PKG_VERSION"));
    println!("{}", tr!("Разовый сканер Windows: майнеры и подозрительное ПО.\n", "One-shot Windows scanner for miners and suspicious software.\n"));
    println!("{}", tr!("  --full            проверить все диски (по умолчанию — пользовательские папки)", "  --full            scan all fixed drives (default: user folders)"));
    println!("{}", tr!("  --path ПАПКА      проверить только эту папку (можно несколько раз)", "  --path DIR        scan only this folder (repeatable)"));
    println!("{}", tr!("  --threads N       число потоков (по умолчанию 1–3)", "  --threads N       worker threads (default 1-3)"));
    println!("{}", tr!("  --report          только отчёт, без карантина", "  --report          report only, no quarantine"));
    println!("{}", tr!("  --ask             спрашивать перед каждым карантином", "  --ask             confirm each quarantine action"));
    println!("{}", tr!("  --offline         без онлайн-проверки (Касперский/VirusTotal)", "  --offline         skip online checks (Kaspersky/VirusTotal)"));
    println!("{}", tr!("  --log ФАЙЛ        сохранить отчёт в файл", "  --log FILE        save the report to a file"));
    println!("{}", tr!("  --no-pause        не ждать Enter в конце", "  --no-pause        do not wait for Enter at the end"));
    println!("{}", tr!("  --lang КОД        язык: en ru uk de es fr pt pl tr zh", "  --lang CODE       language: en ru uk de es fr pt pl tr zh"));
    println!("{}", tr!("  --allow ПУТЬ      добавить файл/папку в белый список и выйти", "  --allow PATH      add a file/folder to the allowlist and exit"));
    println!("{}", tr!("  --quarantine      показать, что лежит в карантине", "  --quarantine      list quarantined items"));
    println!("{}", tr!("  --restore         вернуть всё из карантина на место", "  --restore         restore everything from quarantine"));
    println!("{}", tr!("  --version, --help", "  --version, --help"));
}

fn ask(q: &str) -> bool {
    print!("{}", q);
    let _ = io::stdout().flush();
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
    matches!(s.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да" | "т" | "так" | "j" | "ja" | "s" | "si" | "sí" | "sim" | "o" | "oui" | "t" | "tak" | "e" | "evet" | "是")
}

fn main() {
    win::setup_console();
    let args: Vec<String> = std::env::args().collect();
    let lang_arg = args.iter().position(|a| a == "--lang").and_then(|i| args.get(i + 1)).map(|s| s.to_lowercase());
    set_lang(lang_arg.as_deref().and_then(Lang::from_code).unwrap_or_else(win::system_lang));
    let has = |f: &str| args.iter().any(|a| a == f);
    let val = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
    if has("--help") || has("-h") || has("/?") {
        print_help();
        return;
    }
    if has("--version") {
        println!("sweep {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Some(p) = val("--allow") {
        add_allow(&p);
        return;
    }
    if has("--restore") {
        restore_all();
        return;
    }
    if has("--quarantine") {
        list_quarantine();
        return;
    }
    let offline = has("--offline");
    let no_pause = has("--no-pause");
    let log_path = val("--log");
    let paths: Vec<PathBuf> = args.windows(2).filter(|w| w[0] == "--path").map(|w| PathBuf::from(&w[1])).collect();
    let allow = load_allow();
    let full = args.iter().any(|a| a == "--full");
    let ask_mode = args.iter().any(|a| a == "--ask");
    let report_only = args.iter().any(|a| a == "--report");
    let threads = args
        .iter()
        .position(|a| a == "--threads")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(|| {
            let c = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
            (c / 2).clamp(1, 3)
        });

    win::set_background();
    let t0 = Instant::now();
    println!("{CYN}sweep{R} {}", tr!("— разовый сканер. Режим: {}, потоков: {}", "— one-shot scanner. Mode: {}, threads: {}", if full { tr!("полный", "full") } else { tr!("быстрый", "quick") }, threads));
    if !win::is_admin() {
        println!("{DIM}{}{R}", tr!("запущен не от администратора: часть служб/задач может быть не видна", "not running as administrator: some services/tasks may be hidden"));
    }

    let wd = windir();
    let me = std::env::current_exe().map(|p| p.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut sys = System::new();
    print!("{}", tr!("Смотрю запущенные процессы и автозапуск… ", "Checking processes and autostart… "));
    let _ = io::stdout().flush();
    let (hot, notes) = collect_hot(&mut sys);
    println!("{}", tr!("{} шт.", "{} items", hot.len()));

    print!("{}", tr!("Собираю список файлов… ", "Collecting files… "));
    let _ = io::stdout().flush();
    let roots = if paths.is_empty() { scan_roots(full) } else { paths.clone() };
    let files = collect_files(&roots, &wd, full);
    println!("{}", tr!("{} шт.", "{} items", files.len()));

    // очередь сканирования
    let mut jobs: Vec<(PathBuf, Option<HotInfo>)> = hot.values().map(|(p, h)| (p.clone(), Some(h.clone()))).collect();
    let hot_keys: HashSet<String> = hot.keys().cloned().collect();
    for f in files {
        if !hot_keys.contains(&f.to_string_lossy().to_lowercase()) {
            jobs.push((f, None));
        }
    }

    let pats = miner_strings();
    let names = miner_names();
    let cmds = miner_cmd();
    let idx = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let results: Mutex<Vec<Analysis>> = Mutex::new(vec![]);
    let total = jobs.len();

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = idx.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                let (p, h) = &jobs[i];
                let lp = p.to_string_lossy().to_lowercase();
                if allow.iter().any(|w| lp == *w || lp.starts_with(&format!("{}\\", w.trim_end_matches('\\')))) {
                    done.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if let Some(a) = analyze(p, h.as_ref(), &pats, &names, &cmds, &wd, &me) {
                    results.lock().unwrap().push(a);
                }
                done.fetch_add(1, Ordering::Relaxed);
            });
        }
        while done.load(Ordering::Relaxed) < total {
            let d = done.load(Ordering::Relaxed);
            let pct = if total > 0 { d * 100 / total } else { 100 };
            let filled = pct / 4;
            print!("\r[{}{}] {:>3}%  {}/{}  {}s ", "#".repeat(filled), "-".repeat(25 - filled), pct, d, total, t0.elapsed().as_secs());
            let _ = io::stdout().flush();
            std::thread::sleep(Duration::from_millis(250));
        }
        println!("\r[{}] 100%  {}/{}  {}s      ", "#".repeat(25), total, total, t0.elapsed().as_secs());
    });

    let mut res = results.into_inner().unwrap();

    // вердикты
    let kl = key_from("KL_KEY", "kl.key");
    let vt = key_from("VT_KEY", "vt.key");
    if !offline {
        online_check(&mut res, kl.as_deref(), vt.as_deref());
    }

    res.sort_by(|a, b| b.score.cmp(&a.score));
    let bad: Vec<&Analysis> = res.iter().filter(|a| a.score >= 8).collect();
    let sus: Vec<&Analysis> = res.iter().filter(|a| a.score >= 3 && a.score < 8).collect();

    println!();
    if bad.is_empty() && sus.is_empty() {
        println!("{GRN}{}{R}", tr!("Угроз и майнеров не найдено.", "No threats or miners found."));
    }
    let describe = |a: &Analysis| {
        let (c, p, d) = &a.info;
        let mut what = vec![];
        for x in [c, p, d] {
            if !x.is_empty() {
                what.push(x.as_str());
            }
        }
        if what.is_empty() { tr!("нет данных о программе", "no program information") } else { what.join(" / ") }
    };
    for a in bad.iter().chain(sus.iter()) {
        let (col, tag) = if a.score >= 8 { (RED, tr!("УГРОЗА", "THREAT")) } else { (YEL, tr!("ПОДОЗРИТЕЛЬНО", "SUSPICIOUS")) };
        println!("{col}[{tag}] {}{R}  ({} {})", a.path.display(), tr!("оценка", "score"), a.score);
        println!("   {}: {}", tr!("что это", "what it is"), describe(a));
        for r in &a.reasons {
            println!("   - {}", r);
        }
        if let Some(h) = &a.hot {
            println!("   {}: {}", tr!("где", "where"), h.sources.join(", "));
        }
        for o in &a.online {
            println!("   {}: {}", tr!("онлайн", "online"), o);
        }
    }

    // неподписанные без признаков
    let unk: Vec<&Analysis> = res.iter().filter(|a| a.score < 3 && a.hot.is_some()).collect();
    if !unk.is_empty() {
        println!("\n{DIM}{}{R}", tr!("Неподписанные программы в работе/автозапуске, признаков угрозы нет ({}):", "Unsigned programs running/autostarting, no threat indicators ({}):", unk.len()));
        for a in unk.iter().take(25) {
            println!("{DIM}  {}  — {}{R}", a.path.display(), describe(a));
        }
    }

    if !bad.is_empty() && !report_only {
        println!();
        for a in &bad {
            let go = !ask_mode || ask(&tr!("Остановить и убрать в карантин {}? [y/N] ", "Stop and quarantine {}? [y/N] ", a.path.display()));
            if go {
                match quarantine(a, &sys) {
                    Ok(d) => println!("{GRN}   {} → {}{R}", tr!("готово", "done"), d.display()),
                    Err(e) => println!("{RED}   {}: {}{R}", tr!("не вышло", "failed"), e),
                }
            }
        }
        println!("{DIM}{}{R}", tr!("Карантин: %LOCALAPPDATA%\\sweep\\quarantine (manifest.txt — откуда что взято)", "Quarantine: %LOCALAPPDATA%\\sweep\\quarantine (manifest.txt lists original paths)"));
    }

    if !notes.is_empty() {
        println!("\n{YEL}{}{R}", tr!("Заметки по системе:", "System notes:"));
        for n in &notes {
            println!("{YEL}  ! {}{R}", n);
        }
    }

    println!("\n{}", tr!("Готово за {} с.", "Done in {} s.", t0.elapsed().as_secs()));
    if let Some(lp) = &log_path {
        let mut rep = format!("sweep {} — {}\n\n", env!("CARGO_PKG_VERSION"), tr!("отчёт", "report"));
        for a in res.iter().filter(|a| a.score >= 3) {
            let tag = if a.score >= 8 { tr!("УГРОЗА", "THREAT") } else { tr!("ПОДОЗРИТЕЛЬНО", "SUSPICIOUS") };
            rep.push_str(&format!("[{}] {}  ({} {})\n   {}: {}\n", tag, a.path.display(), tr!("оценка", "score"), a.score, tr!("что это", "what it is"), describe(a)));
            for r in &a.reasons {
                rep.push_str(&format!("   - {}\n", r));
            }
            if !a.sha.is_empty() {
                rep.push_str(&format!("   sha256: {}\n", a.sha));
            }
        }
        for n in &notes {
            rep.push_str(&format!("! {}\n", n));
        }
        match fs::write(lp, rep) {
            Ok(_) => println!("{}", tr!("Отчёт сохранён: {}", "Report saved: {}", lp)),
            Err(e) => println!("{RED}{}: {}{R}", tr!("не удалось сохранить отчёт", "could not save report"), e),
        }
    }
    if !no_pause && win::own_console() {
        print!("{}", tr!("Нажми Enter для выхода…", "Press Enter to exit…"));
        let _ = io::stdout().flush();
        let mut s = String::new();
        let _ = io::stdin().read_line(&mut s);
    }
}
