// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // OpenSSH launches this executable with a short-lived, authenticated IPC
    // endpoint, never a password. Exit before logging, plugins or the GUI.
    if let Some(code) = codeg_lib::ssh::askpass_client::run_if_requested() {
        std::process::exit(i32::from(code));
    }

    // When called as a git credential helper, handle it immediately and exit.
    // This avoids starting the full Tauri GUI runtime.
    if std::env::args().any(|a| a == "--credential-helper") {
        // Subprocess mode, before the desktop logging init in `run()`: install a
        // stderr-only subscriber so helper diagnostics aren't dropped, while
        // stdout stays the git credential protocol channel.
        let _log_guard = codeg_lib::logging::init::init_stderr_only();
        codeg_lib::git_credential::run_credential_helper();
        return;
    }

    codeg_lib::run()
}
