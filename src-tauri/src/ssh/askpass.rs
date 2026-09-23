//! App-owned OpenSSH askpass bridge. A one-time capability protects a bounded
//! loopback socket. Only the initiating webview may answer a pending prompt.
//! Passwords never enter argv, environment variables, the database or logs.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use super::askpass_client::{valid_answer, AskpassRequest, ADDRESS_ENV, ANSWER_TIMEOUT, FRAME_LIMIT, TOKEN_ENV};
use crate::app_error::AppCommandError;

pub const PROMPT_EVENT: &str = "ssh-auth://prompt";
pub const DISMISS_EVENT: &str = "ssh-auth://dismiss";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PromptKind {
    Password,
    Passphrase,
    HostKey,
}

fn prompt_kind(prompt: &str) -> Option<PromptKind> {
    let text = prompt.trim();
    if text.contains("Are you sure you want to continue connecting")
        && text.contains("SHA256:")
    {
        Some(PromptKind::HostKey)
    } else if text.starts_with("Enter passphrase for key '") && text.ends_with(":") {
        Some(PromptKind::Passphrase)
    } else if text.ends_with("'s password:") {
        Some(PromptKind::Password)
    } else {
        // Keyboard-interactive is deliberately disabled. Do not mistake an
        // arbitrary server-supplied challenge for an OpenSSH password prompt.
        None
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptPayload {
    pub request_id: String,
    pub owner_window: String,
    pub host: String,
    pub kind: PromptKind,
    pub prompt: String,
    pub expires_at: i64,
}

#[async_trait]
pub trait PromptHandler: Send + Sync {
    async fn request(
        &self,
        owner_window: &str,
        host: &str,
        kind: PromptKind,
        prompt: &str,
    ) -> Option<Zeroizing<String>>;
}

struct PendingPrompt {
    payload: PromptPayload,
    response: oneshot::Sender<Option<Zeroizing<String>>>,
}

#[derive(Default)]
pub struct PromptBroker {
    app: Mutex<Option<AppHandle>>,
    pending: Mutex<HashMap<String, PendingPrompt>>,
}

impl PromptBroker {
    pub fn bind_app(&self, app: &AppHandle) {
        *self.app.lock().unwrap() = Some(app.clone());
    }

    pub fn available(&self) -> bool {
        self.app.lock().unwrap().is_some()
    }

    pub fn list(&self, owner_window: &str) -> Vec<PromptPayload> {
        self.pending.lock().unwrap().values()
            .filter(|entry| entry.payload.owner_window == owner_window)
            .map(|entry| entry.payload.clone()).collect()
    }

    pub fn answer(
        &self,
        owner_window: &str,
        request_id: &str,
        answer: Option<String>,
    ) -> Result<(), AppCommandError> {
        let answer = answer.map(Zeroizing::new);
        let mut pending = self.pending.lock().unwrap();
        let Some(entry) = pending.get(request_id) else { return Ok(()); };
        if entry.payload.owner_window != owner_window {
            return Err(AppCommandError::authentication_failed("This SSH prompt belongs to another window"));
        }
        if answer.as_ref().is_some_and(|value| !valid_answer(value)
            || (entry.payload.kind == PromptKind::HostKey && value.as_str() != "yes"))
        {
            return Err(AppCommandError::invalid_input("Invalid SSH prompt response"));
        }
        let entry = pending.remove(request_id).expect("checked above");
        let expired = entry.payload.expires_at <= chrono::Utc::now().timestamp_millis();
        let _ = entry.response.send(if expired { None } else { answer });
        Ok(())
    }
}

struct PendingGuard<'a> {
    broker: &'a PromptBroker,
    app: AppHandle,
    owner_window: String,
    request_id: String,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.broker.pending.lock().unwrap().remove(&self.request_id);
        let _ = self.app.emit_to(&self.owner_window, DISMISS_EVENT,
            serde_json::json!({ "requestId": self.request_id, "ownerWindow": self.owner_window }));
    }
}

#[async_trait]
impl PromptHandler for PromptBroker {
    async fn request(
        &self,
        owner_window: &str,
        host: &str,
        kind: PromptKind,
        prompt: &str,
    ) -> Option<Zeroizing<String>> {
        let app = self.app.lock().unwrap().clone()?;
        app.get_webview_window(owner_window)?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let payload = PromptPayload {
            request_id: request_id.clone(), owner_window: owner_window.into(),
            host: host.into(), kind, prompt: prompt.into(),
            expires_at: chrono::Utc::now().timestamp_millis() + ANSWER_TIMEOUT.as_millis() as i64,
        };
        let (response, receiver) = oneshot::channel();
        // Bound the queue even if many connection operations arrive together.
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.len() >= 16 { return None; }
            pending.insert(request_id.clone(), PendingPrompt { payload: payload.clone(), response });
        }
        let _guard = PendingGuard {
            broker: self, app: app.clone(), owner_window: owner_window.into(), request_id,
        };
        app.emit_to(owner_window, PROMPT_EVENT, &payload).ok()?;
        let waiting = tokio::time::timeout(ANSWER_TIMEOUT, receiver);
        tokio::pin!(waiting);
        let mut window_check = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                result = &mut waiting => return result.ok()?.ok()?,
                _ = window_check.tick() => { app.get_webview_window(owner_window)?; }
            }
        }
    }
}

/// Scoped to a single profile/configuration and the lifetime of its windows.
/// Exact OpenSSH prompts distinguish target/jump-host passwords and key files.
/// Host-key approvals are NEVER cached here: OpenSSH writes known_hosts itself.
#[derive(Default)]
pub struct CredentialCache {
    answers: Mutex<HashMap<String, Zeroizing<String>>>,
    declined: AtomicBool,
}

impl CredentialCache {
    pub fn clear(&self) {
        self.answers.lock().unwrap().clear();
    }

    pub fn redact(&self, text: &str) -> String {
        let mut redacted = text.to_string();
        for secret in self.answers.lock().unwrap().values() {
            if !secret.is_empty() { redacted = redacted.replace(secret.as_str(), "[REDACTED]"); }
        }
        redacted
    }
}

pub struct AskpassServer {
    address: String,
    token: String,
    helper: PathBuf,
    task: JoinHandle<()>,
    credentials: Arc<CredentialCache>,
    failure: Arc<Mutex<Option<&'static str>>>,
}

impl Drop for AskpassServer {
    fn drop(&mut self) {
        // Dropping the listener's JoinSet also drops every in-flight prompt
        // guard, dismisses its UI, closes helper sockets and releases answers.
        self.task.abort();
    }
}

impl AskpassServer {
    pub async fn start(
        helper: PathBuf,
        host: String,
        owner_window: String,
        prompter: Arc<dyn PromptHandler>,
        credentials: Arc<CredentialCache>,
    ) -> Result<Self, AppCommandError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| {
            AppCommandError::io_error("Could not create the local SSH authentication channel")
        })?;
        let address = listener.local_addr().map_err(|_| AppCommandError::io_error("Could not read the SSH authentication endpoint"))?.to_string();
        let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
        let failure = Arc::new(Mutex::new(None));
        let context = Arc::new(ServerContext {
            token: token.clone(), host, owner_window, prompter,
            credentials: credentials.clone(), failure: failure.clone(),
            requests: AtomicUsize::new(0),
        });
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(4));
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket, peer)) = accepted else { break; };
                        if !peer.ip().is_loopback() { continue; }
                        let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                        let context = context.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let _ = tokio::time::timeout(ANSWER_TIMEOUT + Duration::from_secs(5),
                                serve_request(socket, &context)).await;
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        Ok(Self { address, token, helper, task, credentials, failure })
    }

    pub fn apply(&self, command: &mut tokio::process::Command) {
        command.env("SSH_ASKPASS", &self.helper)
            .env("SSH_ASKPASS_REQUIRE", "force")
            // Unix OpenSSH also checks DISPLAY; no actual X server is used.
            .env("DISPLAY", std::env::var_os("DISPLAY").unwrap_or_else(|| "codeg:0".into()))
            .env("LC_ALL", "C").env("LANG", "C")
            .env(ADDRESS_ENV, &self.address).env(TOKEN_ENV, &self.token);
    }

    pub fn failure(&self) -> Option<AppCommandError> {
        self.failure.lock().unwrap().map(AppCommandError::authentication_failed)
    }

    pub fn redact(&self, text: &str) -> String { self.credentials.redact(text) }
}

struct ServerContext {
    token: String,
    host: String,
    owner_window: String,
    prompter: Arc<dyn PromptHandler>,
    credentials: Arc<CredentialCache>,
    failure: Arc<Mutex<Option<&'static str>>>,
    requests: AtomicUsize,
}

impl ServerContext {
    async fn answer(&self, prompt: &str) -> Option<Zeroizing<String>> {
        if self.credentials.declined.load(Ordering::Relaxed) {
            *self.failure.lock().unwrap() = Some("SSH authentication was cancelled. Close and reopen the workspace to try again.");
            return None;
        }
        let Some(kind) = prompt_kind(prompt) else {
            *self.failure.lock().unwrap() = Some("Unsupported SSH authentication prompt. Use password or key authentication; keyboard-interactive MFA is not supported.");
            return None;
        };
        if kind != PromptKind::HostKey {
            let cached = self.credentials.answers.lock().unwrap().get(prompt).cloned();
            if cached.is_some() { return cached; }
        }
        let answer = tokio::time::timeout(ANSWER_TIMEOUT,
            self.prompter.request(&self.owner_window, &self.host, kind, prompt))
            .await.ok().flatten();
        let Some(answer) = answer else {
            self.credentials.declined.store(true, Ordering::Relaxed);
            *self.failure.lock().unwrap() = Some("SSH authentication was cancelled or timed out. Reconnect to try again.");
            return None;
        };
        if !valid_answer(&answer) || (kind == PromptKind::HostKey && answer.as_str() != "yes") {
            *self.failure.lock().unwrap() = Some("The SSH prompt response was not accepted");
            return None;
        }
        if kind != PromptKind::HostKey {
            self.credentials.answers.lock().unwrap().insert(prompt.to_string(), answer.clone());
        }
        Some(answer)
    }
}

async fn serve_request(mut socket: TcpStream, context: &ServerContext) -> std::io::Result<()> {
    let (reader, mut writer) = socket.split();
    let mut frame = Vec::new();
    tokio::time::timeout(Duration::from_secs(3),
        BufReader::new(reader.take((FRAME_LIMIT + 1) as u64)).read_until(b'\n', &mut frame))
        .await.map_err(std::io::Error::other)??;
    if frame.len() > FRAME_LIMIT || frame.last() != Some(&b'\n') { return Ok(()); }
    let Ok(request) = serde_json::from_slice::<AskpassRequest>(&frame) else { return Ok(()); };
    if request.token != context.token { return Ok(()); }
    if context.requests.fetch_add(1, Ordering::Relaxed) >= 16 { return Ok(()); }
    let answer = context.answer(&request.prompt).await;
    #[derive(Serialize)]
    struct Reply<'a> { answer: Option<&'a str> }
    let mut frame = Zeroizing::new(serde_json::to_vec(&Reply {
        answer: answer.as_ref().map(|secret| secret.as_str()),
    })?);
    frame.push(b'\n');
    writer.write_all(&frame).await
}

#[cfg(test)]
#[path = "askpass_tests.rs"]
mod tests;
