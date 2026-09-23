//! App-owned SSH tunnels. Only locators are persisted; every proxy operation
//! resolves the current database row under a per-profile gate. Retiring a gate
//! cancels in-flight bootstrap work, so edits/deletes cannot orphan a tunnel.
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use sea_orm::DatabaseConnection;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::app_error::AppCommandError;
use crate::db::service::remote_workspace_connection_service;
use crate::models::{RemoteWorkspaceConnectionInfo, RemoteWorkspaceSshConfig};
use crate::ssh::bootstrap::{run_bootstrap, BootstrapOutcome};
use crate::ssh::command::{ssh_command, SshInvocation};

const TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(25);
const HEALTH_INTERVAL: Duration = Duration::from_secs(3);
const STDERR_LIMIT: usize = 8192;

struct ActiveTunnel {
    local_port: u16,
    token: String,
    config: RemoteWorkspaceSshConfig,
    child: Child,
    last_health: Instant,
    stderr: Arc<StdMutex<Vec<u8>>>,
    stderr_task: tokio::task::JoinHandle<()>,
}

impl Drop for ActiveTunnel {
    fn drop(&mut self) {
        // kill_on_drop owns only this local SSH child, never the remote server.
        let _ = self.child.start_kill();
        self.stderr_task.abort();
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
    cancelled: CancellationToken,
}

impl SshSession {
    fn new() -> Self {
        Self {
            tunnel: Mutex::new(None),
            cancelled: CancellationToken::new(),
        }
    }

    async fn run<T>(&self, action: impl Future<Output = Result<T, AppCommandError>>) -> Result<T, AppCommandError> {
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
}

pub struct SshManager {
    // Never held across an await. Window destruction can cancel synchronously,
    // before a new window with the same label registers a different instance.
    state: StdMutex<ManagerState>,
    health: reqwest::Client,
    cancelled: CancellationToken,
}

impl SshManager {
    pub fn new() -> Self {
        Self {
            state: StdMutex::new(ManagerState::default()),
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
        if state.closing {
            return Err(AppCommandError::network("The desktop is shutting down"));
        }
        Ok(state.sessions.entry(id).or_insert_with(|| Arc::new(SshSession::new())).clone())
    }

    pub fn register_window(&self, id: i32, instance: &str) {
        self.state.lock().unwrap().windows.entry(id).or_default().insert(instance.to_string());
    }

    pub fn window_closed(&self, id: i32, instance: &str) {
        let retired = {
            let mut state = self.state.lock().unwrap();
            let Some(windows) = state.windows.get_mut(&id) else { return };
            if !windows.remove(instance) || !windows.is_empty() {
                return;
            }
            state.windows.remove(&id);
            let session = state.sessions.remove(&id);
            if let Some(session) = &session {
                session.cancelled.cancel();
            }
            session
        };
        if let Some(session) = retired {
            tauri::async_runtime::spawn(async move { session.stop().await; });
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
        session.run(async {
            let mut tunnel = session.tunnel.lock().await;
            let mut connection = remote_workspace_connection_service::get(db, id)
                .await?
                .ok_or_else(|| AppCommandError::not_found(format!("Remote connection {id} not found")))?;
            let Some(config) = connection.ssh.as_ref() else {
                *tunnel = None;
                return Ok(connection);
            };
            let reusable = match tunnel.as_mut() {
                Some(active) if &active.config == config => active.healthy(&self.health).await,
                _ => false,
            };
            if !reusable {
                *tunnel = None;
                let outcome = run_bootstrap(config).await?;
                *tunnel = Some(self.open_tunnel(config, &outcome).await?);
            }
            let active = tunnel.as_ref().expect("tunnel established above");
            connection.base_url = active.base_url();
            connection.token = active.token.clone();
            Ok(connection)
        }).await
    }

    /// Save/test uses a temporary tunnel: a successful form submission must not
    /// leave an unowned local listener when no workspace window is open.
    pub async fn test_config(&self, config: &RemoteWorkspaceSshConfig) -> Result<(), AppCommandError> {
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Err(AppCommandError::network("The desktop is shutting down")),
            result = async {
                let config = crate::ssh::config::validate_ssh_config(config)?;
                let outcome = run_bootstrap(&config).await?;
                let mut tunnel = self.open_tunnel(&config, &outcome).await?;
                let _ = tunnel.child.kill().await;
                Ok(())
            } => result,
        }
    }

    async fn open_tunnel(&self, config: &RemoteWorkspaceSshConfig, outcome: &BootstrapOutcome) -> Result<ActiveTunnel, AppCommandError> {
        let mut detail = String::new();
        for _ in 0..3 {
            let local_port = pick_local_port().await?;
            let mut command = ssh_command(config, SshInvocation::Tunnel { local_port, remote_port: outcome.port }, None);
            command.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            let mut child = command.spawn().map_err(|e| AppCommandError::io_error(
                "Could not start the system ssh client",
            ).with_detail(e.to_string()))?;
            let mut stderr_pipe = child.stderr.take().expect("stderr is piped");
            let stderr = Arc::new(StdMutex::new(Vec::new()));
            let log = stderr.clone();
            // Drain for the full lifetime, not only after exit: an SSH config
            // with verbose logging must not fill its pipe and freeze the tunnel.
            let stderr_task = tokio::spawn(async move {
                let mut chunk = [0u8; 1024];
                while let Ok(size) = stderr_pipe.read(&mut chunk).await {
                    if size == 0 { break; }
                    let mut buffer = log.lock().unwrap();
                    buffer.extend_from_slice(&chunk[..size]);
                    let excess = buffer.len().saturating_sub(STDERR_LIMIT);
                    buffer.drain(..excess);
                }
            });
            let mut active = ActiveTunnel {
                local_port, token: outcome.token.clone(), config: config.clone(), child,
                last_health: Instant::now() - HEALTH_INTERVAL, stderr, stderr_task,
            };
            let ready = tokio::time::timeout(TUNNEL_READY_TIMEOUT, async {
                loop {
                    if active.exited() { return false; }
                    if tunnel_port_open(local_port).await && active.healthy(&self.health).await {
                        return true;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }).await.unwrap_or(false);
            if ready {
                tracing::info!("[SSH] forwarding 127.0.0.1:{local_port} to remote loopback:{}", outcome.port);
                return Ok(active);
            }
            detail = active.error_detail();
            let _ = active.child.kill().await;
        }
        Err(AppCommandError::network("Could not establish an authenticated SSH tunnel")
            .with_detail(if detail.is_empty() { "The SSH forward did not become ready in time".into() } else { detail }))
    }

    pub async fn shutdown(&self, id: i32) {
        let session = {
            let mut state = self.state.lock().unwrap();
            let session = state.sessions.remove(&id);
            if let Some(session) = &session { session.cancelled.cancel(); }
            session
        };
        if let Some(session) = session { session.stop().await; }
    }

    pub async fn shutdown_all(&self) {
        self.cancelled.cancel();
        let sessions = {
            let mut state = self.state.lock().unwrap();
            state.closing = true;
            let sessions = std::mem::take(&mut state.sessions);
            for session in sessions.values() { session.cancelled.cancel(); }
            sessions
        };
        for session in sessions.into_values() { session.stop().await; }
    }
}

impl Default for SshManager {
    fn default() -> Self { Self::new() }
}

async fn health_ok(client: &reqwest::Client, base_url: &str, token: &str) -> bool {
    let Ok(response) = client.post(format!("{base_url}/api/health"))
        .bearer_auth(token).json(&serde_json::json!({})).send().await else { return false };
    if !response.status().is_success() { return false; }
    // Bound the response too; a port collision must not consume arbitrary memory.
    let mut response = response;
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > 16 * 1024 { return false; }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return false,
        }
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else { return false };
    value["status"] == "ok" && value["version"] == env!("CARGO_PKG_VERSION")
}

async fn pick_local_port() -> Result<u16, AppCommandError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await
        .map_err(|e| AppCommandError::io_error("Could not reserve an SSH tunnel port").with_detail(e.to_string()))?;
    listener.local_addr().map(|addr| addr.port())
        .map_err(|e| AppCommandError::io_error("Could not read the SSH tunnel port").with_detail(e.to_string()))
}

async fn tunnel_port_open(port: u16) -> bool {
    matches!(tokio::time::timeout(Duration::from_millis(500),
        tokio::net::TcpStream::connect(("127.0.0.1", port))).await, Ok(Ok(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }).await.unwrap();
    }

    #[tokio::test]
    async fn retiring_a_session_cancels_in_flight_and_queued_work() {
        let manager = Arc::new(SshManager::new());
        let session = manager.session(1).unwrap();
        let worker_session = session.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            worker_session.run(async {
                let _held = worker_session.tunnel.lock().await;
                started.send(()).unwrap();
                std::future::pending::<Result<(), AppCommandError>>().await
            }).await
        });
        ready.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), manager.shutdown(1)).await.unwrap();
        assert!(worker.await.unwrap().is_err());
        assert!(session.run(async { Ok(()) }).await.is_err());
        assert!(!Arc::ptr_eq(&session, &manager.session(1).unwrap()));
        manager.shutdown_all().await;
        assert!(manager.session(1).is_err());
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn resolves_latest_http_row_and_never_resurrects_a_deleted_profile() {
        let db = crate::db::test_helpers::fresh_in_memory_db().await;
        let manager = SshManager::new();
        let row = remote_workspace_connection_service::create(&db.conn, "test", "http://localhost:1234", "old", &[], None).await.unwrap();
        assert_eq!(manager.resolve_connection(&db.conn, row.id).await.unwrap().token, "old");
        remote_workspace_connection_service::update(&db.conn, row.id, "test", "http://localhost:1235", "new", &[], None).await.unwrap();
        let next = manager.resolve_connection(&db.conn, row.id).await.unwrap();
        assert_eq!(next.token, "new");
        assert_eq!(next.base_url, "http://localhost:1235");
        remote_workspace_connection_service::delete(&db.conn, row.id).await.unwrap();
        manager.shutdown(row.id).await;
        assert!(manager.resolve_connection(&db.conn, row.id).await.is_err());
    }
}
