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
