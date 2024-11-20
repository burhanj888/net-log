use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: NaiveDateTime,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct NetworkAction {
    pub id: i32,
    pub action: String,
    pub performed_by: String,
    pub timestamp: NaiveDateTime,
}
