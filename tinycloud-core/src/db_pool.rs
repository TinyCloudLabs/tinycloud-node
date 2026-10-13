//! The node's shared database pool connection (TC-951).

use std::{future::Future, pin::Pin};

use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr,
    ExecResult, IsolationLevel, QueryResult, Statement, TransactionError, TransactionTrait,
};

/// The node's pooled database connection.
///
/// Every production component that talks to the node's capability database
/// holds this type rather than a raw [`DatabaseConnection`], so all
/// statements and transactions on the shared pool go through one place.
#[derive(Clone, Debug)]
pub struct RecoveringConnection {
    conn: DatabaseConnection,
}

impl RecoveringConnection {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self { conn }
    }

    /// The underlying sea-orm connection.
    pub fn sea_orm_connection(&self) -> &DatabaseConnection {
        &self.conn
    }
}

impl From<DatabaseConnection> for RecoveringConnection {
    fn from(conn: DatabaseConnection) -> Self {
        Self::new(conn)
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for RecoveringConnection {
    fn get_database_backend(&self) -> DatabaseBackend {
        self.conn.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.conn.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.conn.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.conn.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.conn.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.conn.support_returning()
    }

    fn is_mock_connection(&self) -> bool {
        self.conn.is_mock_connection()
    }
}

#[async_trait::async_trait]
impl TransactionTrait for RecoveringConnection {
    async fn begin(&self) -> Result<DatabaseTransaction, DbErr> {
        self.conn.begin().await
    }

    async fn begin_with_config(
        &self,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<DatabaseTransaction, DbErr> {
        self.conn
            .begin_with_config(isolation_level, access_mode)
            .await
    }

    async fn transaction<F, T, E>(&self, callback: F) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        self.conn.transaction(callback).await
    }

    async fn transaction_with_config<F, T, E>(
        &self,
        callback: F,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        self.conn
            .transaction_with_config(callback, isolation_level, access_mode)
            .await
    }
}
