use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The SSH locator for a connection reached over `ssh` instead of a
        // user-supplied URL: a JSON object `{"host","username","port",
        // "identityFile"}`.
        //
        // Nullable with no default, unlike the `headers` column next to it. The
        // absence of a value is the meaningful state here: NULL means "this is a
        // plain HTTP connection", which is what every row written before this
        // migration is, and what the model deserializes to `None`. A
        // `DEFAULT '{}'` would turn all of them into malformed SSH profiles.
        manager
            .alter_table(
                Table::alter()
                    .table(RemoteWorkspaceConnection::Table)
                    .add_column(ColumnDef::new(RemoteWorkspaceConnection::SshConfig).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RemoteWorkspaceConnection::Table)
                    .drop_column(RemoteWorkspaceConnection::SshConfig)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum RemoteWorkspaceConnection {
    Table,
    SshConfig,
}
