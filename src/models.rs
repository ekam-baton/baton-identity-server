use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub phone_number: Option<String>,
    pub password_hash: String,
    pub encrypted_key_backup: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub subscription_status: String,
    pub subscription_expiry: Option<DateTime<Utc>>,
    pub is_verified: bool,
    pub failed_login_attempts: i32,
    pub lockout_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub phone_number: Option<String>,
    pub password: String,
    pub encrypted_key_backup: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPlayRequest {
    pub purchase_token: String,
    pub product_id: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub refresh_token: String,
    pub user_id: Uuid,
    pub subscription_status: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RecoverResponse {
    pub encrypted_key_backup: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadKeysRequest {
    pub identity_key: String,
    pub signed_pre_key: String,
    pub signature: String,
    pub one_time_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct KeysResponse {
    pub identity_key: String,
    pub signed_pre_key: String,
    pub signature: String,
    pub one_time_key: Option<String>,
}
