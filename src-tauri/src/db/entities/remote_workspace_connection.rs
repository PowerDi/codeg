use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "remote_workspace_connection")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    pub base_url: String,
    #[sea_orm(column_type = "Text")]
    pub token: String,
    /// JSON `Vec<RemoteWorkspaceHeader>` — extra headers the desktop client
    /// sends on every request to this connection.
    #[sea_orm(column_type = "Text")]
    pub headers: String,
    /// JSON `RemoteWorkspaceSshConfig` when this connection is reached over
    /// SSH, `NULL` for a plain HTTP one.
    ///
    /// Nullable rather than defaulted to `'null'`: every row written before this
    /// column existed reads back as `None`, which is exactly "a plain HTTP
    /// connection" — so the upgrade needs no backfill and old records keep their
    /// original behaviour. Only a locator lives here; the key is referenced by
    /// path and the remote token is re-read over SSH on every connect, so this
    /// column holds no credential.
    #[sea_orm(column_type = "Text", nullable)]
    pub ssh_config: Option<String>,
    pub sort_order: i32,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
