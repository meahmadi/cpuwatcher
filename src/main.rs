#![windows_subsystem = "windows"]  // comment this out while debugging to see a console

use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use sysinfo::{ProcessesToUpdate, Process, Pid, System};

// ---------------- CONFIG ----------------

const CPU_THRESHOLD: f32 = 10.0;          // % CPU for killing watchlisted processes
const SECS_THRESHOLD: u64 = 5;            // seconds above threshold before killing

const DISCOVER_CPU_THRESHOLD: f32 = 10.0; // % CPU for discovering new processes
const DISCOVER_SECS_THRESHOLD: u64 = 10;  // seconds above threshold before commenting in file

const POLL_INTERVAL: Duration = Duration::from_millis(1000); // 1s polling

// ---------------- PATH HELPERS ----------------

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn watchlist_path() -> PathBuf {
    let mut p = exe_dir();
    p.push("watchlist.txt");
    p
}

fn log_path() -> PathBuf {
    let mut p = exe_dir();
    p.push("cpu_watcher.log");
    p
}

fn tray_icon_path() -> PathBuf {
    let mut p = exe_dir();
    p.push("tray.ico"); // this must sit next to the EXE
    p
}

// ---------------- LOGGING ----------------

fn log_line(msg: &str) {
    let path = log_path();
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(file, "[{}] {}", ts, msg);
    }
}

// ---------------- WATCHLIST ----------------

fn ensure_watchlist_exists(path: &Path) {
    if path.exists() {
        return;
    }

    let default_content = "\
# watchlist.txt
# One process name per line (case-insensitive).
# Example:
# chrome.exe
# notepad.exe
";

    match fs::write(path, default_content) {
        Ok(_) => log_line(&format!(
            "Created default watchlist file at {:?}",
            path
        )),
        Err(e) => log_line(&format!(
            "ERROR: Could not create default watchlist at {:?}: {}",
            path, e
        )),
    }
}

/// Active (uncommented) names – these are the ones we actually kill.
fn read_active_watchlist(path: &Path) -> Vec<String> {
    match fs::read_to_string(path) {
        Ok(contents) => contents
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect(),
        Err(e) => {
            log_line(&format!(
                "ERROR: Could not read watchlist file {:?}: {}",
                path, e
            ));
            Vec::new()
        }
    }
}

/// All names (uncommented AND commented) that look like process names.
/// Used to avoid adding duplicates when we discover new processes.
fn read_all_known_names(path: &Path) -> HashSet<String> {
    let mut set = HashSet::new();

    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return set,
    };

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Strip leading '#' and any text like "discovered:" etc.
        let cleaned = trimmed.trim_start_matches('#').trim();
        if let Some(last) = cleaned.split_whitespace().last() {
            if last.to_lowercase().ends_with(".exe") {
                set.insert(last.to_lowercase());
            }
        }
    }

    set
}

/// case-insensitive name match against active watchlist entries.
fn name_matches_watchlist(process: &Process, watchlist: &[String]) -> bool {
    let proc_name = process.name().to_string_lossy().to_lowercase();
    watchlist
        .iter()
        .any(|w| w.to_lowercase() == proc_name)
}

// ---------------- PROCESS KILL ----------------

fn kill_process(process: &Process) {
    let pid: Pid = process.pid();
    let name = process.name().to_string_lossy();

    log_line(&format!("Killing process '{}' (PID {})", name, pid));

    if !process.kill() {
        log_line(&format!(
            "Failed to send kill signal to PID {} ('{}')",
            pid, name
        ));
    }
}

// ---------------- DISCOVERY ----------------

fn append_discovered_process(name: &str) {
    let path = watchlist_path();
    let line = format!("# discovered: {}\n", name);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        if let Err(e) = file.write_all(line.as_bytes()) {
            log_line(&format!(
                "ERROR: Failed to append discovered process '{}' to watchlist: {}",
                name, e
            ));
        } else {
            log_line(&format!(
                "Discovered new high-CPU process, commented in watchlist: {}",
                name
            ));
        }
    } else {
        log_line(&format!(
            "ERROR: Could not open watchlist to append discovered process '{}'",
            name
        ));
    }
}

// ---------------- MONITOR THREAD ----------------

fn run_monitor_loop(running: Arc<AtomicBool>) {
    let w_path = watchlist_path();
    ensure_watchlist_exists(&w_path);

    let mut active_watchlist = read_active_watchlist(&w_path);
    let mut known_names = read_all_known_names(&w_path);

    let mut last_watchlist_mtime: Option<SystemTime> =
        fs::metadata(&w_path).and_then(|m| m.modified()).ok();

    if active_watchlist.is_empty() {
        log_line("Watchlist is empty at startup; nothing will be auto-killed until you add entries.");
    } else {
        log_line("Initial active watchlist loaded:");
        for n in &active_watchlist {
            log_line(&format!("  - {}", n));
        }
    }

    let mut system = System::new_all();

    // For processes IN watchlist
    let mut high_cpu_watchlisted: HashMap<Pid, Instant> = HashMap::new();
    // For processes NOT in watchlist
    let mut high_cpu_unlisted: HashMap<Pid, Instant> = HashMap::new();

    while running.load(Ordering::Relaxed) {
        // Reload watchlist if modified
        if let Ok(meta) = fs::metadata(&w_path) {
            if let Ok(modified) = meta.modified() {
                let should_reload = match last_watchlist_mtime {
                    None => true,
                    Some(old) => modified > old,
                };

                if should_reload {
                    active_watchlist = read_active_watchlist(&w_path);
                    known_names = read_all_known_names(&w_path);
                    last_watchlist_mtime = Some(modified);

                    log_line("Reloaded watchlist.txt:");
                    if active_watchlist.is_empty() {
                        log_line("  (active list now empty)");
                    } else {
                        for n in &active_watchlist {
                            log_line(&format!("  active: {}", n));
                        }
                    }
                }
            }
        }

        system.refresh_processes(ProcessesToUpdate::All, true);
        let now = Instant::now();

        for (pid, process) in system.processes() {
            let proc_name = process.name().to_string_lossy().to_string();
            let proc_name_lc = proc_name.to_lowercase();
            let cpu = process.cpu_usage();

            // 1) Watchlisted → killing logic
            if name_matches_watchlist(process, &active_watchlist) {
                if cpu >= CPU_THRESHOLD {
                    let entry = high_cpu_watchlisted.entry(*pid).or_insert(now);
                    let elapsed = now.duration_since(*entry).as_secs();

                    if elapsed >= SECS_THRESHOLD {
                        log_line(&format!(
                            "Process '{}' (PID {}) over {}% CPU for {}s (actual {:.1}%) -> killing (watchlisted)",
                            proc_name,
                            pid,
                            CPU_THRESHOLD,
                            SECS_THRESHOLD,
                            cpu
                        ));
                        kill_process(process);
                        high_cpu_watchlisted.remove(pid);
                    }
                } else {
                    high_cpu_watchlisted.remove(pid);
                }
                continue;
            }

            // 2) Not in watchlist → discovery logic
            if cpu >= DISCOVER_CPU_THRESHOLD {
                let entry = high_cpu_unlisted.entry(*pid).or_insert(now);
                let elapsed = now.duration_since(*entry).as_secs();

                if elapsed >= DISCOVER_SECS_THRESHOLD {
                    if !known_names.contains(&proc_name_lc) {
                        append_discovered_process(&proc_name);
                        known_names.insert(proc_name_lc.clone());
                    }
                    high_cpu_unlisted.remove(pid);
                }
            } else {
                high_cpu_unlisted.remove(pid);
            }
        }

        thread::sleep(POLL_INTERVAL);
    }

    log_line("Monitor thread stopping (running flag = false).");
}

// ---------------- LOG FILE OPEN ----------------

fn open_log_file() {
    let path = log_path();
    let path_str = path.to_string_lossy().to_string();

    let _ = Command::new("cmd")
        .args(["/C", "start", "", &path_str])
        .spawn();
}

// ---------------- REAL MAIN (TRAY + MONITOR) ----------------

fn real_main() -> Result<(), systray::Error> {
    let running = Arc::new(AtomicBool::new(true));
    let monitor_running = running.clone();

    // Start background monitor thread
    let monitor_handle = thread::spawn(move || run_monitor_loop(monitor_running));

    // Tray icon app
    let mut app = systray::Application::new().map_err(|e| {
        log_line(&format!("Failed to create tray application: {}", e));
        e
    })?;

    app.set_tooltip(&"CPU Watcher".to_string())?;

    // Set tray icon from file next to the EXE
    let icon_path = tray_icon_path();
    if let Some(icon_str) = icon_path.to_str() {
        if let Err(e) = app.set_icon_from_file(icon_str) {
            log_line(&format!(
                "Failed to set tray icon from file {:?}: {}",
                icon_path, e
            ));
            // continue without custom icon
        }
    } else {
        log_line("Failed to convert tray icon path to string");
    }

    // Open log menu item
    app.add_menu_item("Open log file", |_| {
        open_log_file();
        Ok::<_, systray::Error>(())
    })?;

    // Exit menu item
    let running_for_exit = running.clone();
    app.add_menu_item("Exit", move |window| {
        running_for_exit.store(false, Ordering::Relaxed);
        window.quit();
        Ok::<_, systray::Error>(())
    })?;

    // Block until user chooses "Exit"
    app.wait_for_message()?;

    let _ = monitor_handle.join();

    Ok(())
}

// ---------------- ENTRYPOINT ----------------

fn main() {
    if let Err(e) = real_main() {
        // If you comment out the windows_subsystem attribute,
        // this will also print to the console for debugging.
        eprintln!("cpu_watcher failed: {}", e);
        log_line(&format!("cpu_watcher failed: {}", e));
    }
}
