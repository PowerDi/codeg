//! App-owned SSH tunnels. Only locators are persisted; every proxy operation
//! resolves the current database row under a per-profile gate. Retiring a gate
//! cancels in-flight bootstrap work, so edits/deletes cannot orphan a tunnel.
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use sea_orm::DatabaseConnection;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::app_error::AppCommandError;
use crate::db::service::remote_workspace_connection_service;
use crate::models::{RemoteWorkspaceConnectionInfo, RemoteWorkspaceSshConfig};
use crate::ssh::askpass::{AskpassServer, CredentialCache, PromptBroker};
use crate::ssh::bootstrap::{
    run_bootstrap_with_askpass, run_bootstrap_with_askpass_and_progress, BootstrapOutcome,
    BootstrapProgress,
};
use crate::ssh::command::{ssh_command_with_askpass, SshInvocation};

const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(25);
const HEALTH_INTERVAL: Duration = Duration::from_secs(3);
const STDERR_LIMIT: usize = 8192;
const TUNNEL_READY_LINE: &str = "CODEG_TUNNEL_READY";
// OpenSSH sets up forwards before executing this command. With
// ExitOnForwardFailure, the ack cannot arrive if another process stole the
// selected port. Never send a bearer token merely because that port is open.
// Keep the parent's stdin pipe open; on disconnect, cat sees EOF and exits.
const TUNNEL_COMMAND: &str = "sh -c 'printf \"CODEG_TUNNEL_READY\\n\"; cat >/dev/null'";

fn ssh_password_secret_name(config: &RemoteWorkspaceSshConfig) -> Option<String> {
    config
        .credential_id
        .as_ref()
        .map(|id| format!("ssh-password:{id}"))
}

struct ActiveTunnel {
    local_port: u16,
    token: String,
    config: RemoteWorkspaceSshConfig,
    child: Child,
    last_health: Instant,
    stderr: Arc<StdMutex<Vec<u8>>>,
    stderr_task: tokio::task::JoinHandle<()>,
    stdout_task: tokio::task::JoinHandle<()>,
}

impl Drop for ActiveTunnel {
    fn drop(&mut self) {
        // kill_on_drop owns only this local SSH child, never the remote server.
        let _ = self.child.start_kill();
        self.stderr_task.abort();
        self.stdout_task.abort();
    }
}

impl ActiveTunnel {
    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.local_port)
    }

    fn exited(&mut self) -> bool {
        !matches!(self.child.try_wait(), Ok(None))
    }

    fn error_detail(&self) -> String {
        let buffer = self.stderr.lock().unwrap();
        crate::ssh::redact::truncate_for_detail(&crate::ssh::redact::redact_secrets(
            String::from_utf8_lossy(&buffer).trim(),
        ))
    }

    async fn healthy(&mut self, client: &reqwest::Client) -> bool {
        if self.exited() {
            return false;
        }
        if self.last_health.elapsed() < HEALTH_INTERVAL {
            return true;
        }
        if !health_ok(client, &self.base_url(), &self.token).await {
            return false;
        }
        self.last_health = Instant::now();
        !self.exited()
    }
}

struct SshSession {
    tunnel: Mutex<Option<ActiveTunnel>>,
    credentials: Arc<CredentialCache>,
    auth_config: StdMutex<Option<RemoteWorkspaceSshConfig>>,
    prompt_window: StdMutex<Option<String>>,
    cancelled: CancellationToken,
}

impl SshSession {
    fn new() -> Self {
        Self {
            tunnel: Mutex::new(None),
            credentials: Arc::new(CredentialCache::default()),
            auth_config: StdMutex::new(None),
            prompt_window: StdMutex::new(None),
            cancelled: CancellationToken::new(),
        }
    }

    async fn run<T>(
        &self,
        action: impl Future<Output = Result<T, AppCommandError>>,
    ) -> Result<T, AppCommandError> {
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Err(AppCommandError::network(
                "The remote connection was closed or changed; reconnect to try again",
            )),
            result = action => result,
        }
    }

    async fn stop(&self) {
        self.cancelled.cancel();
        self.credentials.clear();
        if let Some(mut active) = self.tunnel.lock().await.take() {
            let _ = active.child.kill().await;
        }
    }
}

#[derive(Default)]
struct ManagerState {
    sessions: HashMap<i32, Arc<SshSession>>,
    windows: HashMap<i32, HashSet<String>>,
    closing: bool,
    closed_profiles: HashSet<i32>,
}

struct FormCredentialCache {
    config: RemoteWorkspaceSshConfig,
    credentials: Arc<CredentialCache>,
}

pub struct SshManager {
    // Never held across an await. Window destruction can cancel synchronously,
    // before a new window with the same label registers a different instance.
    state: StdMutex<ManagerState>,
    // Test/save share answers only while the owning management dialog is open.
    // The cache itself is never persisted; opted-in passwords are copied to
    // the OS credential store only after a successful save/open.
    form_credentials: StdMutex<HashMap<String, FormCredentialCache>>,
    pub(crate) prompts: Arc<PromptBroker>,
    health: reqwest::Client,
    cancelled: CancellationToken,
}

impl SshManager {
    pub fn new() -> Self {
        Self {
            state: StdMutex::new(ManagerState::default()),
            form_credentials: StdMutex::new(HashMap::new()),
            prompts: Arc::new(PromptBroker::default()),
            cancelled: CancellationToken::new(),
            health: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()
                .expect("failed to build SSH health client"),
        }
    }

    fn session(&self, id: i32) -> Result<Arc<SshSession>, AppCommandError> {
        let mut state = self.state.lock().unwrap();
        if state.closing || state.closed_profiles.contains(&id) {
            return Err(AppCommandError::network("The remote workspace is closed"));
        }
        Ok(state
            .sessions
            .entry(id)
            .or_insert_with(|| Arc::new(SshSession::new()))
            .clone())
    }

    pub fn set_prompt_window(&self, id: i32, label: &str) {
        if let Ok(session) = self.session(id) {
            *session.prompt_window.lock().unwrap() = Some(label.to_string());
        }
    }

    async fn askpass(
        &self,
        config: &RemoteWorkspaceSshConfig,
        owner_window: &str,
        credentials: Arc<CredentialCache>,
    ) -> Result<Option<AskpassServer>, AppCommandError> {
        credentials.set_persistent_secret(if config.remember_password {
            ssh_password_secret_name(config)
        } else {
            None
        });
        // Non-GUI tests keep the existing fail-closed, batch-mode behavior.
        if !self.prompts.available() {
            return Ok(None);
        }
        let helper = std::env::current_exe().map_err(|_| {
            AppCommandError::io_error("Could not locate the SSH authentication helper")
        })?;
        AskpassServer::start(
            helper,
            config.host.clone(),
            owner_window.into(),
            self.prompts.clone(),
            credentials,
        )
        .await
        .map(Some)
    }

    pub fn register_window(&self, id: i32, instance: &str) {
        let mut state = self.state.lock().unwrap();
        state.closed_profiles.remove(&id);
        state
            .windows
            .entry(id)
            .or_default()
            .insert(instance.to_string());
    }

    pub fn window_closed(&self, id: i32, instance: &str) {
        let retired = {
            let mut state = self.state.lock().unwrap();
            let Some(windows) = state.windows.get_mut(&id) else {
                return;
            };
            if !windows.remove(instance) || !windows.is_empty() {
                return;
            }
            state.windows.remove(&id);
            state.closed_profiles.insert(id);
            let session = state.sessions.remove(&id);
            if let Some(session) = &session {
                session.cancelled.cancel();
            }
            session
        };
        if let Some(session) = retired {
            tauri::async_runtime::spawn(async move {
                session.stop().await;
            });
        }
    }

    /// Fetch *inside* the gate. Fetching a row before acquiring it would allow
    /// an old in-flight request to resurrect a deleted/edited SSH profile.
    pub async fn resolve_connection(
        &self,
        db: &DatabaseConnection,
        id: i32,
    ) -> Result<RemoteWorkspaceConnectionInfo, AppCommandError> {
        let session = self.session(id)?;
        session
            .run(async {
                let mut tunnel = session.tunnel.lock().await;
                let mut connection = remote_workspace_connection_service::get(db, id)
                    .await?
                    .ok_or_else(|| {
                        AppCommandError::not_found(format!("Remote connection {id} not found"))
                    })?;
                let Some(config) = connection.ssh.as_ref() else {
                    *tunnel = None;
                    session.credentials.clear();
                    return Ok(connection);
                };
                let reusable = match tunnel.as_mut() {
                    Some(active) if &active.config == config => active.healthy(&self.health).await,
                    _ => false,
                };
                if !reusable {
                    *tunnel = None;
                    {
                        let mut previous = session.auth_config.lock().unwrap();
                        if previous.as_ref() != Some(config) {
                            session.credentials.clear();
                            *previous = Some(config.clone());
                        }
                    }
                    let window = session
                        .prompt_window
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| format!("remote-workspace-{id}"));
                    let askpass = self
                        .askpass(config, &window, session.credentials.clone())
                        .await?;
                    let result: Result<ActiveTunnel, AppCommandError> = async {
                        let outcome = run_bootstrap_with_askpass(config, askpass.as_ref()).await?;
                        let tunnel = self.open_tunnel(config, &outcome, askpass.as_ref()).await?;
                        session.credentials.persist_passwords().map_err(|detail| {
                            AppCommandError::task_execution_failed(
                                "Could not save the SSH password to the system credential store",
                            )
                            .with_detail(detail)
                        })?;
                        Ok(tunnel)
                    }
                    .await;
                    if result.is_err() {
                        session.credentials.clear();
                    }
                    *tunnel = Some(result?);
                }
                let active = tunnel.as_ref().expect("tunnel established above");
                connection.base_url = active.base_url();
                connection.token = active.token.clone();
                Ok(connection)
            })
            .await
    }

    /// Save/test uses a temporary tunnel: a successful form submission must not
    /// leave an unowned local listener when no workspace window is open.
    pub async fn test_config(
        &self,
        config: &RemoteWorkspaceSshConfig,
    ) -> Result<(), AppCommandError> {
        self.test_config_for_window(config, "main").await
    }

    pub async fn test_config_for_window(
        &self,
        config: &RemoteWorkspaceSshConfig,
        owner_window: &str,
    ) -> Result<(), AppCommandError> {
        self.test_config_for_window_with_progress(config, owner_window, None, false)
            .await
    }

    fn form_credentials(
        &self,
        owner_window: &str,
        config: &RemoteWorkspaceSshConfig,
    ) -> Arc<CredentialCache> {
        let mut caches = self.form_credentials.lock().unwrap();
        if let Some(entry) = caches.get(owner_window) {
            if &entry.config == config {
                return entry.credentials.clone();
            }
        }
        let credentials = Arc::new(CredentialCache::default());
        caches.insert(
            owner_window.to_string(),
            FormCredentialCache {
                config: config.clone(),
                credentials: credentials.clone(),
            },
        );
        credentials
    }

    pub fn clear_form_credentials(&self, owner_window: &str) {
        if let Some(entry) = self.form_credentials.lock().unwrap().remove(owner_window) {
            entry.credentials.clear();
        }
    }

    pub fn delete_saved_password(&self, config: &RemoteWorkspaceSshConfig) -> Result<(), String> {
        let Some(name) = ssh_password_secret_name(config) else {
            return Ok(());
        };
        crate::keyring_store::delete_secret(&name)
    }

    pub async fn test_config_for_window_with_progress(
        &self,
        config: &RemoteWorkspaceSshConfig,
        owner_window: &str,
        progress: Option<BootstrapProgress>,
        persist_passwords: bool,
    ) -> Result<(), AppCommandError> {
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Err(AppCommandError::network("The desktop is shutting down")),
            result = async {
                if let Some(report) = progress.as_ref() {
                    report("Validating SSH configuration".to_string());
                }
                let config = crate::ssh::config::validate_ssh_config(config)?;
                if let Some(report) = progress.as_ref() {
                    report(format!("Connecting to {}", config.host));
                }
                let credentials = self.form_credentials(owner_window, &config);
                let askpass = self
                    .askpass(&config, owner_window, credentials.clone())
                    .await?;
                let result = async {
                    let outcome = run_bootstrap_with_askpass_and_progress(
                        &config,
                        askpass.as_ref(),
                        progress.as_ref(),
                    )
                    .await?;
                    if let Some(report) = progress.as_ref() {
                        report("Opening encrypted SSH tunnel".to_string());
                    }
                    let mut tunnel = self.open_tunnel(&config, &outcome, askpass.as_ref()).await?;
                    if let Some(report) = progress.as_ref() {
                        report("SSH tunnel established; remote server is ready".to_string());
                    }
                    let _ = tunnel.child.kill().await;
                    if persist_passwords {
                        credentials.persist_passwords().map_err(|detail| {
                            AppCommandError::task_execution_failed(
                                "Could not save the SSH password to the system credential store",
                            )
                            .with_detail(detail)
                        })?;
                    }
                    Ok(())
                }
                .await;
                if askpass.as_ref().and_then(|auth| auth.failure()).is_some() {
                    self.clear_form_credentials(owner_window);
                }
                result
            } => result,
        }
    }

    async fn open_tunnel(
        &self,
        config: &RemoteWorkspaceSshConfig,
        outcome: &BootstrapOutcome,
        askpass: Option<&AskpassServer>,
    ) -> Result<ActiveTunnel, AppCommandError> {
        let mut detail = String::new();
        for _ in 0..3 {
            let local_port = pick_local_port().await?;
            let mut command = ssh_command_with_askpass(
                config,
                SshInvocation::Tunnel {
                    local_port,
                    remote_port: outcome.port,
                },
                Some(TUNNEL_COMMAND),
                askpass,
            );
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            let mut child = command.spawn().map_err(|e| {
                AppCommandError::io_error("Could not start the system ssh client")
                    .with_detail(e.to_string())
            })?;
            let mut stdout_pipe = child.stdout.take().expect("stdout is piped");
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let stdout_task = tokio::spawn(async move {
                let ready = read_forward_ready(&mut stdout_pipe).await;
                let _ = ready_tx.send(ready);
                if ready {
                    let _ = tokio::io::copy(&mut stdout_pipe, &mut tokio::io::sink()).await;
                }
            });
            let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
            let stderr = Arc::new(StdMutex::new(Vec::new()));
            let log = stderr.clone();
            // Drain for the full lifetime, not only after exit: an SSH config
            // with verbose logging must not fill its pipe and freeze the tunnel.
            let stderr_task = tokio::spawn(async move {
                let mut chunk = [0u8; 1024];
                while let Ok(size) = stderr_pipe.read(&mut chunk).await {
                    if size == 0 {
                        break;
                    }
                    let mut buffer = log.lock().unwrap();
                    buffer.extend_from_slice(&chunk[..size]);
                    let excess = buffer.len().saturating_sub(STDERR_LIMIT);
                    buffer.drain(..excess);
                }
            });
            let mut active = ActiveTunnel {
                local_port,
                token: outcome.token.clone(),
                config: config.clone(),
                child,
                last_health: Instant::now() - HEALTH_INTERVAL,
                stderr,
                stderr_task,
                stdout_task,
            };
            let ready_timeout = if askpass.is_some() {
                Duration::from_secs(240)
            } else {
                TUNNEL_READY_TIMEOUT
            };
            let ready = tokio::time::timeout(ready_timeout, async {
                if !ready_rx.await.unwrap_or(false) || active.exited() {
                    return false;
                }
                active.healthy(&self.health).await
            })
            .await
            .unwrap_or(false);
            if ready {
                tracing::info!(
                    "[SSH] forwarding 127.0.0.1:{local_port} to remote loopback:{}",
                    outcome.port
                );
                return Ok(active);
            }
            detail = active.error_detail();
            if let Some(auth) = askpass {
                detail = auth.redact(&detail);
            }
            let _ = active.child.kill().await;
            if let Some(error) = askpass.and_then(|auth| auth.failure()) {
                return Err(error);
            }
            if detail.to_ascii_lowercase().contains("permission denied") {
                return Err(crate::ssh::command::classify_ssh_failure(&detail, None));
            }
        }
        Err(
            AppCommandError::network("Could not establish an authenticated SSH tunnel")
                .with_detail(if detail.is_empty() {
                    "The SSH forward did not become ready in time".into()
                } else {
                    detail
                }),
        )
    }

    /// Network reconnects retire only the tunnel, not the session's in-memory
    /// password or prompt owner. Edit/delete/last-window-close still clear all.
    pub async fn reset_tunnel(&self, id: i32) {
        let session = self.state.lock().unwrap().sessions.get(&id).cloned();
        if let Some(session) = session {
            if let Some(mut active) = session.tunnel.lock().await.take() {
                let _ = active.child.kill().await;
            }
        }
    }

    pub async fn shutdown(&self, id: i32) {
        let session = {
            let mut state = self.state.lock().unwrap();
            let session = state.sessions.remove(&id);
            if let Some(session) = &session {
                session.cancelled.cancel();
            }
            session
        };
        if let Some(session) = session {
            session.stop().await;
        }
    }

    pub async fn shutdown_all(&self) {
        self.cancelled.cancel();
        self.prompts.shutdown();
        let form_credentials = std::mem::take(&mut *self.form_credentials.lock().unwrap());
        for entry in form_credentials.into_values() {
            entry.credentials.clear();
        }
        let sessions = {
            let mut state = self.state.lock().unwrap();
            state.closing = true;
            let sessions = std::mem::take(&mut state.sessions);
            for session in sessions.values() {
                session.cancelled.cancel();
            }
            sessions
        };
        for session in sessions.into_values() {
            session.stop().await;
        }
    }
}

impl Default for SshManager {
    fn default() -> Self {
        Self::new()
    }
}

async fn health_ok(client: &reqwest::Client, base_url: &str, token: &str) -> bool {
    let Ok(response) = client
        .post(format!("{base_url}/api/health"))
        .bearer_auth(token)
        .json(&serde_json::json!({}))
        .send()
        .await
    else {
        return false;
    };
    if !response.status().is_success() {
        return false;
    }
    // Bound the response too; a port collision must not consume arbitrary memory.
    let mut response = response;
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > 16 * 1024 {
                    return false;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return false,
        }
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return false;
    };
    value["status"] == "ok" && value["version"] == env!("CARGO_PKG_VERSION")
}

async fn pick_local_port() -> Result<u16, AppCommandError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| {
        AppCommandError::io_error("Could not reserve an SSH tunnel port").with_detail(e.to_string())
    })?;
    listener.local_addr().map(|addr| addr.port()).map_err(|e| {
        AppCommandError::io_error("Could not read the SSH tunnel port").with_detail(e.to_string())
    })
}

// Consume only a bounded banner before the machine-readable acknowledgement.
async fn read_forward_ready(stdout: &mut (impl AsyncRead + Unpin)) -> bool {
    let mut lines = BufReader::new(stdout.take(64 * 1024)).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line == TUNNEL_READY_LINE {
            return true;
        }
    }
    false
}

#[cfg(test)]
async fn tunnel_port_open(port: u16) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(("127.0.0.1", port))
        )
        .await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_password_key_is_scoped_to_the_profile_credential_id() {
        let base = RemoteWorkspaceSshConfig {
            host: "build-host".to_string(),
            username: Some("coder".to_string()),
            remember_password: true,
            credential_id: Some("73baf9d8-b681-4f2f-bf89-4ece1396fc65".into()),
            ..Default::default()
        };
        let renamed_target = RemoteWorkspaceSshConfig {
            host: "other-host".to_string(),
            ..base.clone()
        };
        assert_eq!(
            ssh_password_secret_name(&base),
            ssh_password_secret_name(&renamed_target)
        );
        assert_ne!(
            ssh_password_secret_name(&base),
            ssh_password_secret_name(&RemoteWorkspaceSshConfig {
                credential_id: Some("015e9e37-d6a5-4f8e-8126-a35dc52b0791".into()),
                ..base
            })
        );
    }

    #[test]
    fn form_credentials_are_reused_only_for_the_same_window_and_config() {
        let manager = SshManager::new();
        let config = RemoteWorkspaceSshConfig {
            host: "build-host".to_string(),
            ..Default::default()
        };
        let first = manager.form_credentials("main", &config);
        let same = manager.form_credentials("main", &config);
        assert!(Arc::ptr_eq(&first, &same));

        let changed = manager.form_credentials(
            "main",
            &RemoteWorkspaceSshConfig {
                port: Some(2222),
                ..config.clone()
            },
        );
        assert!(!Arc::ptr_eq(&first, &changed));

        let other_window = manager.form_credentials("settings", &config);
        assert!(!Arc::ptr_eq(&changed, &other_window));
        manager.clear_form_credentials("main");
        assert!(!Arc::ptr_eq(
            &changed,
            &manager.form_credentials("main", &config)
        ));
    }

    #[tokio::test]
    async fn forwarding_needs_an_ack_not_just_an_open_port() {
        let mut good = &b"login banner\nCODEG_TUNNEL_READY\n"[..];
        assert!(read_forward_ready(&mut good).await);
        let mut unrelated = &b"HTTP/1.1 200 OK\n"[..];
        assert!(!read_forward_ready(&mut unrelated).await);
        let large = vec![b'x'; 128 * 1024];
        assert!(!read_forward_ready(&mut large.as_slice()).await);
    }

    #[tokio::test]
    async fn port_probe_distinguishes_listening_from_closed() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(tunnel_port_open(port).await);
        drop(listener);
        assert!(!tunnel_port_open(port).await);
        assert_ne!(pick_local_port().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn sessions_are_reused_and_other_hosts_are_not_blocked() {
        let manager = SshManager::new();
        let one = manager.session(1).unwrap();
        assert!(Arc::ptr_eq(&one, &manager.session(1).unwrap()));
        let _busy = one.tunnel.lock().await;
        tokio::time::timeout(Duration::from_secs(1), async {
            let other = manager.session(2).unwrap();
            let _guard = other.tunnel.lock().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retiring_a_session_cancels_in_flight_and_queued_work() {
        let manager = Arc::new(SshManager::new());
        let session = manager.session(1).unwrap();
        let worker_session = session.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            worker_session
                .run(async {
                    let _held = worker_session.tunnel.lock().await;
                    started.send(()).unwrap();
                    std::future::pending::<Result<(), AppCommandError>>().await
                })
                .await
        });
        ready.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), manager.shutdown(1))
            .await
            .unwrap();
        assert!(worker.await.unwrap().is_err());
        assert!(session.run(async { Ok(()) }).await.is_err());
        assert!(!Arc::ptr_eq(&session, &manager.session(1).unwrap()));
        manager.shutdown_all().await;
        assert!(manager.session(1).is_err());
    }

    #[tokio::test]
    async fn last_window_close_tombstones_late_requests_but_not_a_reopened_window() {
        let manager = SshManager::new();
        manager.register_window(1, "old");
        manager.register_window(1, "new");
        let session = manager.session(1).unwrap();
        manager.window_closed(1, "old");
        assert!(!session.cancelled.is_cancelled());
        manager.window_closed(1, "new");
        assert!(session.cancelled.is_cancelled());
        assert!(manager.session(1).is_err());
        manager.register_window(1, "reopened");
        manager.window_closed(1, "old");
        assert!(manager.session(1).is_ok());
        manager.shutdown_all().await;
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn resolves_latest_http_row_and_never_resurrects_a_deleted_profile() {
        let db = crate::db::test_helpers::fresh_in_memory_db().await;
        let manager = SshManager::new();
        let row = remote_workspace_connection_service::create(
            &db.conn,
            "test",
            "http://localhost:1234",
            "old",
            &[],
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            manager
                .resolve_connection(&db.conn, row.id)
                .await
                .unwrap()
                .token,
            "old"
        );
        remote_workspace_connection_service::update(
            &db.conn,
            row.id,
            "test",
            "http://localhost:1235",
            "new",
            &[],
            None,
        )
        .await
        .unwrap();
        let next = manager.resolve_connection(&db.conn, row.id).await.unwrap();
        assert_eq!(next.token, "new");
        assert_eq!(next.base_url, "http://localhost:1235");
        remote_workspace_connection_service::delete(&db.conn, row.id)
            .await
            .unwrap();
        manager.shutdown(row.id).await;
        assert!(manager.resolve_connection(&db.conn, row.id).await.is_err());
    }
}
