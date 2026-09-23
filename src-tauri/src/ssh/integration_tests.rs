//! Runs only against the disposable SSH server created by the CI harness.
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::tungstenite::{http::HeaderMap, Message};

use super::{bootstrap::run_bootstrap, tunnel::SshManager};
use crate::commands::remote_proxy::{connect_with_subprotocol_auth, http_url_to_ws_url};
use crate::db::service::remote_workspace_connection_service as profiles;
use crate::models::RemoteWorkspaceSshConfig;

async fn websocket_ready(base_url: &str, token: &str) {
    let url = http_url_to_ws_url(base_url);
    let mut socket = tokio::time::timeout(
        Duration::from_secs(10),
        connect_with_subprotocol_auth(&url, token, &HeaderMap::new()),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Text(text) if text.contains("__ready__") => break,
                Message::Ping(payload) => {
                    socket.send(Message::Pong(payload)).await.unwrap();
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    socket.close(None).await.unwrap();
}

#[tokio::test]
#[ignore = "requires scripts/ssh-workspace-ci.sh and an isolated Linux SSH account"]
async fn isolated_sshd_install_reuse_tunnel_and_reconnect() {
    let host = std::env::var("CODEG_SSH_TEST_HOST").expect("use the isolated SSH CI harness");
    assert_eq!(host, "codeg-ssh-ci", "never run against a user's SSH host");
    let config = RemoteWorkspaceSshConfig {
        host,
        ..Default::default()
    };
    // Separate SSH execs race a *cold* installation. Remote flock must allow
    // exactly one start, then let the waiter reuse the same background server.
    let (cold, waiter) = tokio::join!(run_bootstrap(&config), run_bootstrap(&config));
    let cold = cold.unwrap();
    let waiter = waiter.unwrap();
    assert_ne!(cold.reused, waiter.reused);
    assert_eq!(cold.port, waiter.port);
    assert!(cold.token == waiter.token);

    let db = crate::db::test_helpers::fresh_in_memory_db().await;
    let profile = profiles::create(&db.conn, "CI SSH", "", "", &[], Some(&config))
        .await
        .unwrap();
    let manager = SshManager::new();
    manager.register_window(profile.id, "first-window");
    let (first, concurrent) = tokio::join!(
        manager.resolve_connection(&db.conn, profile.id),
        manager.resolve_connection(&db.conn, profile.id)
    );
    let first = first.unwrap();
    let concurrent = concurrent.unwrap();
    assert_eq!(
        first.base_url, concurrent.base_url,
        "concurrent calls must share one tunnel"
    );
    assert!(first.token == concurrent.token);
    assert!(first.base_url.starts_with("http://127.0.0.1:"));
    let saved = profiles::get(&db.conn, profile.id).await.unwrap().unwrap();
    assert!(saved.token.is_empty());
    assert_eq!(saved.base_url, "ssh://codeg-ssh-ci");

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!("{}/api/health", first.base_url);
    assert_eq!(
        client
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let health: serde_json::Value = client
        .post(&url)
        .bearer_auth(&first.token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
    websocket_ready(&first.base_url, &first.token).await;

    let reused = run_bootstrap(&config).await.unwrap();
    assert!(
        reused.reused,
        "a second SSH exec must adopt the background server"
    );
    assert!(reused.token == first.token);

    // Simulate a dropped local transport, then resolve again like the WS loop.
    manager.shutdown(profile.id).await;
    let second = manager
        .resolve_connection(&db.conn, profile.id)
        .await
        .unwrap();
    assert!(
        first.token == second.token,
        "reconnection must retain the remote instance"
    );
    websocket_ready(&second.base_url, &second.token).await;

    manager.window_closed(profile.id, "first-window");
    assert!(
        manager
            .resolve_connection(&db.conn, profile.id)
            .await
            .is_err(),
        "late requests from a closed window must not recreate a tunnel"
    );
    let port = reqwest::Url::parse(&second.base_url)
        .unwrap()
        .port()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        run_bootstrap(&config).await.unwrap().reused,
        "closing local tunnels must leave remote jobs running"
    );

    manager.register_window(profile.id, "reopened-window");
    let reopened = manager
        .resolve_connection(&db.conn, profile.id)
        .await
        .unwrap();
    websocket_ready(&reopened.base_url, &reopened.token).await;
    profiles::delete(&db.conn, profile.id).await.unwrap();
    manager.shutdown(profile.id).await;
    assert!(manager
        .resolve_connection(&db.conn, profile.id)
        .await
        .is_err());
    manager.shutdown_all().await;
}

/// Same OpenSSH executable/builder/bootstrap and askpass client as production,
/// but the UI answers come from a fixture and the account is CI-only.
#[tokio::test]
#[ignore = "requires the disposable password account in scripts/ssh-workspace-ci.sh"]
async fn isolated_sshd_password_host_trust_and_helper() {
    use super::askpass::{AskpassServer, CredentialCache, PromptHandler, PromptKind};
    use super::bootstrap::run_bootstrap_with_askpass;
    use super::command::{ssh_command_with_askpass, SshInvocation};
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncBufReadExt, BufReader};
    use zeroize::Zeroizing;

    struct Answers {
        password: String,
        fingerprint: String,
        decline: bool,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl PromptHandler for Answers {
        async fn request(
            &self,
            _owner: &str,
            _host: &str,
            kind: PromptKind,
            prompt: &str,
        ) -> Option<Zeroizing<String>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.decline {
                return None;
            }
            match kind {
                PromptKind::HostKey => {
                    assert!(
                        prompt.contains(&self.fingerprint),
                        "must display the actual pinned host fingerprint"
                    );
                    Some(Zeroizing::new("yes".into()))
                }
                PromptKind::Password => Some(Zeroizing::new(self.password.clone())),
                PromptKind::Passphrase => panic!("fixture does not use an encrypted key"),
            }
        }
    }
    assert_eq!(
        std::env::var("CODEG_SSH_TEST_HOST").unwrap(),
        "codeg-ssh-ci"
    );
    let helper = PathBuf::from(std::env::var("CODEG_SSH_TEST_HELPER").unwrap());
    let password = std::env::var("CODEG_SSH_TEST_PASSWORD").unwrap();
    let fingerprint = std::env::var("CODEG_SSH_TEST_FINGERPRINT").unwrap();
    let config = RemoteWorkspaceSshConfig {
        host: "codeg-ssh-password-ci".into(),
        ..Default::default()
    };
    // Check the real executable's helper mode independently of SSH, so a
    // missing helper/runtime is distinguishable from host verification errors.
    let probe_answers = Arc::new(Answers {
        password: "helper-probe".into(),
        fingerprint: fingerprint.clone(),
        decline: false,
        calls: AtomicUsize::new(0),
    });
    let probe_auth = AskpassServer::start(
        helper.clone(),
        config.host.clone(),
        "ci".into(),
        probe_answers.clone(),
        Arc::new(CredentialCache::default()),
    )
    .await
    .unwrap();
    let mut probe = crate::process::tokio_command(&helper);
    probe.arg("fixture@localhost's password: ");
    probe_auth.apply(&mut probe);
    let result = tokio::time::timeout(Duration::from_secs(5), probe.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.status.success(),
        "helper entry failed: status={:?}, callbacks={}, stderr={}",
        result.status.code(),
        probe_answers.calls.load(Ordering::Relaxed),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"helper-probe\n");
    drop(probe_auth);

    let denied = Arc::new(Answers {
        password: password.clone(),
        fingerprint: fingerprint.clone(),
        decline: true,
        calls: AtomicUsize::new(0),
    });
    let auth = AskpassServer::start(
        helper.clone(),
        config.host.clone(),
        "ci".into(),
        denied.clone(),
        Arc::new(CredentialCache::default()),
    )
    .await
    .unwrap();
    let refused = run_bootstrap_with_askpass(&config, Some(&auth))
        .await
        .expect_err("declined trust must fail");
    assert_eq!(
        denied.calls.load(Ordering::Relaxed),
        1,
        "declining trust must never ask for a password; initial failure: {refused:?}"
    );
    drop(auth);

    let answers = Arc::new(Answers {
        password,
        fingerprint: fingerprint.clone(),
        decline: false,
        calls: AtomicUsize::new(0),
    });
    let credentials = Arc::new(CredentialCache::default());
    let auth = AskpassServer::start(
        helper.clone(),
        config.host.clone(),
        "ci".into(),
        answers.clone(),
        credentials.clone(),
    )
    .await
    .unwrap();
    let outcome = run_bootstrap_with_askpass(&config, Some(&auth))
        .await
        .unwrap();
    assert_eq!(
        answers.calls.load(Ordering::Relaxed),
        2,
        "one fingerprint confirmation and one password"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut command = ssh_command_with_askpass(
        &config,
        SshInvocation::Tunnel {
            local_port: port,
            remote_port: outcome.port,
        },
        Some("sh -c 'echo CODEG_PASSWORD_TUNNEL; cat >/dev/null'"),
        Some(&auth),
    );
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(20), stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line.trim(), "CODEG_PASSWORD_TUNNEL");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let response = client
        .post(format!("http://127.0.0.1:{port}/api/health"))
        .bearer_auth(&outcome.token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        answers.calls.load(Ordering::Relaxed),
        2,
        "tunnel reuses the in-memory password"
    );
    child.kill().await.unwrap();
    drop(auth);

    let auth = AskpassServer::start(
        helper.clone(),
        config.host.clone(),
        "ci".into(),
        answers.clone(),
        credentials.clone(),
    )
    .await
    .unwrap();
    run_bootstrap_with_askpass(&config, Some(&auth))
        .await
        .unwrap();
    assert_eq!(
        answers.calls.load(Ordering::Relaxed),
        2,
        "recreated helpers reuse the same live session"
    );
    credentials.clear();
    run_bootstrap_with_askpass(&config, Some(&auth))
        .await
        .unwrap();
    assert_eq!(
        answers.calls.load(Ordering::Relaxed),
        3,
        "cleared sessions require a fresh password"
    );
    drop(auth);

    let wrong = Arc::new(Answers {
        password: "not-the-fixture-password".into(),
        fingerprint,
        decline: false,
        calls: AtomicUsize::new(0),
    });
    let auth = AskpassServer::start(
        helper.clone(),
        config.host.clone(),
        "ci".into(),
        wrong.clone(),
        Arc::new(CredentialCache::default()),
    )
    .await
    .unwrap();
    let error = run_bootstrap_with_askpass(&config, Some(&auth))
        .await
        .expect_err("wrong password must fail");
    assert!(!error.to_string().contains("not-the-fixture-password"));
    assert_eq!(wrong.calls.load(Ordering::Relaxed), 1);
    drop(auth);

    let changed = RemoteWorkspaceSshConfig {
        host: "codeg-ssh-changed-ci".into(),
        ..Default::default()
    };
    let before = denied.calls.load(Ordering::Relaxed);
    let auth = AskpassServer::start(
        helper,
        changed.host.clone(),
        "ci".into(),
        denied.clone(),
        Arc::new(CredentialCache::default()),
    )
    .await
    .unwrap();
    assert!(run_bootstrap_with_askpass(&changed, Some(&auth))
        .await
        .is_err());
    assert_eq!(
        denied.calls.load(Ordering::Relaxed),
        before,
        "changed host keys must not reach password or trust prompts"
    );
}
