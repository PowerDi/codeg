#[cfg(feature = "tauri-runtime")]
use reqwest::StatusCode;
#[cfg(feature = "tauri-runtime")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "tauri-runtime")]
use std::time::Duration;
#[cfg(feature = "tauri-runtime")]
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

#[cfg(feature = "tauri-runtime")]
use crate::app_error::AppCommandError;
#[cfg(feature = "tauri-runtime")]
use crate::commands::remote_proxy::RemoteProxyState;
#[cfg(feature = "tauri-runtime")]
use crate::db::service::remote_workspace_connection_service;
#[cfg(feature = "tauri-runtime")]
use crate::db::AppDatabase;
#[cfg(feature = "tauri-runtime")]
use crate::models::{
    RemoteWorkspaceConnectionInfo, RemoteWorkspaceHeader, RemoteWorkspaceSshConfig, ToHeaderMap,
};
#[cfg(feature = "tauri-runtime")]
use std::sync::Arc;

#[cfg(feature = "tauri-runtime")]
const REMOTE_HEALTH_TIMEOUT: Duration = Duration::from_secs(8);

#[cfg(feature = "tauri-runtime")]
const SSH_CONNECTION_PROGRESS_EVENT: &str = "ssh-connection://progress";

#[cfg(feature = "tauri-runtime")]
#[derive(Clone, Serialize)]
struct SshConnectionProgressEvent {
    task_id: String,
    message: String,
}

#[cfg(feature = "tauri-runtime")]
fn ssh_progress_reporter(
    window: &tauri::WebviewWindow,
    task_id: Option<String>,
) -> Option<crate::ssh::bootstrap::BootstrapProgress> {
    let task_id = task_id?.trim().to_string();
    if task_id.is_empty() || task_id.len() > 128 {
        return None;
    }
    let app = window.app_handle().clone();
    let owner_window = window.label().to_string();
    Some(Arc::new(move |message| {
        let _ = app.emit_to(
            &owner_window,
            SSH_CONNECTION_PROGRESS_EVENT,
            SshConnectionProgressEvent {
                task_id: task_id.clone(),
                message,
            },
        );
    }))
}

#[cfg(feature = "tauri-runtime")]
pub(crate) fn new_remote_window_instance_id() -> String {
    format!("rw-{}", uuid::Uuid::new_v4().simple())
}

#[cfg(feature = "tauri-runtime")]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteWorkspaceConnectionInput {
    pub name: String,
    #[serde(default, alias = "baseUrl")]
    pub base_url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub headers: Vec<RemoteWorkspaceHeader>,
    #[serde(default)]
    pub ssh: Option<RemoteWorkspaceSshConfig>,
}

#[cfg(feature = "tauri-runtime")]
async fn validate_remote_health(
    base_url: &str,
    token: &str,
    headers: &[RemoteWorkspaceHeader],
) -> Result<(), AppCommandError> {
    let normalized = remote_workspace_connection_service::normalize_base_url(base_url)?;
    let url = format!("{normalized}/api/health");
    let client = reqwest::Client::builder()
        .timeout(REMOTE_HEALTH_TIMEOUT)
        // The health check is the first request to carry the connection's
        // custom headers, and the one the user runs to prove the setup works.
        // It gets the same host pinning as every later request, or "test
        // succeeded" would mean something weaker than "save succeeded".
        .redirect(crate::commands::remote_proxy::connection_redirect_policy())
        .build()
        .map_err(|e| {
            AppCommandError::configuration_invalid("Failed to create remote health client")
                .with_detail(e.to_string())
        })?;
    let headers = remote_workspace_connection_service::validate_headers(headers)?;
    let response = client
        .post(url)
        .bearer_auth(token.trim())
        .headers(headers.to_header_map())
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| {
            AppCommandError::network("Unable to connect to remote workspace")
                .with_detail(crate::commands::remote_proxy::request_error_detail(&e))
        })?;

    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(AppCommandError::authentication_failed(
            "Remote Workspace token is invalid",
        ));
    }

    if !response.status().is_success() {
        return Err(
            AppCommandError::network("Remote Workspace health check failed")
                .with_detail(format!("HTTP {}", response.status())),
        );
    }

    Ok(())
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn list_remote_workspace_connections(
    db: tauri::State<'_, AppDatabase>,
) -> Result<Vec<RemoteWorkspaceConnectionInfo>, AppCommandError> {
    remote_workspace_connection_service::list(&db.conn)
        .await
        .map_err(AppCommandError::db)
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn get_remote_workspace_connection(
    db: tauri::State<'_, AppDatabase>,
    id: i32,
) -> Result<RemoteWorkspaceConnectionInfo, AppCommandError> {
    remote_workspace_connection_service::get(&db.conn, id)
        .await?
        .ok_or_else(|| AppCommandError::not_found(format!("Remote connection {id} not found")))
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn test_remote_workspace_connection(
    window: tauri::WebviewWindow,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
    input: RemoteWorkspaceConnectionInput,
    task_id: Option<String>,
) -> Result<(), AppCommandError> {
    proxy.ssh.prompts.bind_app(window.app_handle());
    let progress = ssh_progress_reporter(&window, task_id);
    validate_connection(&proxy, &input, window.label(), progress, false).await
}

#[cfg(feature = "tauri-runtime")]
async fn validate_connection(
    proxy: &RemoteProxyState,
    input: &RemoteWorkspaceConnectionInput,
    owner_window: &str,
    progress: Option<crate::ssh::bootstrap::BootstrapProgress>,
    persist_password: bool,
) -> Result<(), AppCommandError> {
    match &input.ssh {
        Some(config) => {
            proxy
                .ssh
                .test_config_for_window_with_progress(
                    config,
                    owner_window,
                    progress,
                    persist_password,
                )
                .await
        }
        None => validate_remote_health(&input.base_url, &input.token, &input.headers).await,
    }
}

#[cfg(feature = "tauri-runtime")]
fn same_ssh_locator(a: &RemoteWorkspaceSshConfig, b: &RemoteWorkspaceSshConfig) -> bool {
    a.host == b.host
        && a.username == b.username
        && a.port == b.port
        && a.identity_file == b.identity_file
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn create_remote_workspace_connection(
    window: tauri::WebviewWindow,
    db: tauri::State<'_, AppDatabase>,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
    input: RemoteWorkspaceConnectionInput,
    task_id: Option<String>,
) -> Result<RemoteWorkspaceConnectionInfo, AppCommandError> {
    if input.name.trim().is_empty() {
        return Err(AppCommandError::invalid_input(
            "Remote connection name is required",
        ));
    }
    proxy.ssh.prompts.bind_app(window.app_handle());
    let progress = ssh_progress_reporter(&window, task_id);
    validate_connection(&proxy, &input, window.label(), progress, true).await?;
    remote_workspace_connection_service::create(
        &db.conn,
        &input.name,
        &input.base_url,
        &input.token,
        &input.headers,
        input.ssh.as_ref(),
    )
    .await
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn update_remote_workspace_connection(
    window: tauri::WebviewWindow,
    db: tauri::State<'_, AppDatabase>,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
    id: i32,
    input: RemoteWorkspaceConnectionInput,
    task_id: Option<String>,
) -> Result<RemoteWorkspaceConnectionInfo, AppCommandError> {
    if input.name.trim().is_empty() {
        return Err(AppCommandError::invalid_input(
            "Remote connection name is required",
        ));
    }
    proxy.ssh.prompts.bind_app(window.app_handle());
    let progress = ssh_progress_reporter(&window, task_id);
    let previous = remote_workspace_connection_service::get(&db.conn, id).await?;
    if let (Some(old), Some(new)) = (
        previous.as_ref().and_then(|connection| connection.ssh.as_ref()),
        input.ssh.as_ref(),
    ) {
        if old.credential_id.is_some()
            && old.credential_id == new.credential_id
            && !same_ssh_locator(old, new)
        {
            return Err(AppCommandError::invalid_input(
                "SSH credential id must change when the connection target changes",
            ));
        }
    }
    validate_connection(&proxy, &input, window.label(), progress, true).await?;
    let updated = remote_workspace_connection_service::update(
        &db.conn,
        id,
        &input.name,
        &input.base_url,
        &input.token,
        &input.headers,
        input.ssh.as_ref(),
    )
    .await?;
    let moved = previous.as_ref().is_none_or(|before| {
        before.base_url != updated.base_url
            || before.token != updated.token
            || before.headers != updated.headers
            || before.ssh != updated.ssh
    });
    proxy.invalidate_connection(id).await;
    if let Some(old) = previous.and_then(|connection| connection.ssh) {
        let keep_same = input
            .ssh
            .as_ref()
            .is_some_and(|new| {
                new.remember_password
                    && new.credential_id.is_some()
                    && new.credential_id == old.credential_id
            });
        if old.remember_password && !keep_same {
            if let Err(err) = proxy.ssh.delete_saved_password(&old) {
                tracing::warn!("[SSH] failed to delete replaced saved password: {err}");
            }
        }
    }
    // The built-in browser's tunnel follows the connection to where it now
    // points, rather than staying on the old address until it drops. A
    // rename leaves it be: closing it would cut every live stream of the
    // connection's tabs (a dev server's reload socket among them).
    if moved {
        crate::browser::remote::connection_changed(window.app_handle(), id).await;
    }
    Ok(updated)
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn delete_remote_workspace_connection(
    app: AppHandle,
    db: tauri::State<'_, AppDatabase>,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
    id: i32,
) -> Result<(), AppCommandError> {
    let previous = remote_workspace_connection_service::get(&db.conn, id).await?;
    remote_workspace_connection_service::delete(&db.conn, id)
        .await
        .map_err(AppCommandError::db)?;
    if let Some(config) = previous.and_then(|connection| connection.ssh) {
        if config.remember_password {
            if let Err(err) = proxy.ssh.delete_saved_password(&config) {
                tracing::warn!("[SSH] failed to delete saved password: {err}");
            }
        }
    }
    proxy.close_connection(id).await;
    // What the remote host's pages stored in the built-in browser goes with
    // the connection they were opened through.
    crate::browser::remote::forget_connection(&app, id).await;
    Ok(())
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn reorder_remote_workspace_connections(
    db: tauri::State<'_, AppDatabase>,
    ids: Vec<i32>,
) -> Result<(), AppCommandError> {
    remote_workspace_connection_service::reorder(&db.conn, ids).await
}

#[cfg(feature = "tauri-runtime")]
#[tauri::command]
pub fn clear_ssh_form_credentials(
    window: tauri::WebviewWindow,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
) {
    proxy.ssh.clear_form_credentials(window.label());
}

#[cfg(feature = "tauri-runtime")]
#[cfg_attr(feature = "tauri-runtime", tauri::command)]
pub async fn open_remote_workspace(
    window: tauri::WebviewWindow,
    app: AppHandle,
    db: tauri::State<'_, AppDatabase>,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
    id: i32,
) -> Result<(), AppCommandError> {
    let connection = remote_workspace_connection_service::get(&db.conn, id)
        .await?
        .ok_or_else(|| AppCommandError::not_found(format!("Remote connection {id} not found")))?;

    let label = format!("remote-workspace-{id}");
    if let Some(existing) = app.get_webview_window(&label) {
        let _ = existing.unminimize();
        existing.set_focus().map_err(|e| {
            AppCommandError::window("Failed to focus remote workspace", e.to_string())
        })?;
        return Ok(());
    }

    // Reserve the instance before connecting. A late request from a destroyed
    // window may not resurrect a tunnel; only an explicit new window can.
    let window_instance_id = new_remote_window_instance_id();
    proxy.ssh.prompts.bind_app(&app);
    proxy.ssh.register_window(id, &window_instance_id);
    proxy.ssh.set_prompt_window(id, window.label());
    let ready = async {
        let resolved = proxy.ssh.resolve_connection(&db.conn, id).await?;
        if !resolved.is_ssh() {
            validate_remote_health(&resolved.base_url, &resolved.token, &resolved.headers).await?;
        }
        Ok::<_, AppCommandError>(())
    }
    .await;
    if let Err(err) = ready {
        proxy.ssh.window_closed(id, &window_instance_id);
        return Err(err);
    }
    let url = WebviewUrl::App(
        format!("workspace?remoteConnectionId={id}&remoteWindowId={window_instance_id}").into(),
    );
    let builder = WebviewWindowBuilder::new(&app, &label, url)
        .title(format!("Codeg - {}", connection.name))
        .inner_size(1260.0, 860.0)
        .min_inner_size(400.0, 600.0)
        .center();
    let builder = crate::commands::windows::apply_platform_window_style(builder);
    // Remote workspace windows load the same `/workspace` route with the taller
    // h-10 title bar, so they get the workspace traffic-light position (not the
    // shorter auxiliary-window default).
    #[cfg(target_os = "macos")]
    let builder = builder.traffic_light_position(
        crate::commands::windows::workspace_window_traffic_light_position(),
    );
    let window = match builder.build() {
        Ok(window) => window,
        Err(err) => {
            proxy.ssh.window_closed(id, &window_instance_id);
            return Err(AppCommandError::window(
                "Failed to open remote workspace",
                err.to_string(),
            ));
        }
    };
    proxy.ssh.set_prompt_window(id, window.label());
    if let Some(proxy) =
        app.try_state::<std::sync::Arc<crate::commands::remote_proxy::RemoteProxyState>>()
    {
        proxy
            .inner()
            .register_window_instance_cleanup(&window, window_instance_id);
    }
    crate::commands::windows::post_window_setup(&window);
    Ok(())
}

#[cfg(feature = "tauri-runtime")]
#[tauri::command]
pub fn list_ssh_auth_prompts(
    window: tauri::WebviewWindow,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
) -> Vec<crate::ssh::askpass::PromptPayload> {
    proxy.ssh.prompts.list(window.label())
}

#[cfg(feature = "tauri-runtime")]
#[tauri::command]
pub fn answer_ssh_auth_prompt(
    window: tauri::WebviewWindow,
    proxy: tauri::State<'_, Arc<RemoteProxyState>>,
    request_id: String,
    answer: Option<String>,
) -> Result<(), AppCommandError> {
    proxy
        .ssh
        .prompts
        .answer(window.label(), &request_id, answer)
}
