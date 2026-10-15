mod auth;
mod db;
mod models;
mod email;

use axum::{
    extract::{State, ConnectInfo},
    http::StatusCode,
    routing::{post, get},
    Json, Router,
};
use models::{AuthResponse, ErrorResponse, LoginRequest, RegisterRequest, User, RecoverResponse};
use sqlx::PgPool;
use std::env;
use std::sync::Arc;
use uuid::Uuid;
use tower_http::cors::{Any, CorsLayer, AllowOrigin};
use axum::http::Method;

use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Instant, Duration};

fn extract_client_ip(headers: &axum::http::HeaderMap, remote_addr: Option<SocketAddr>) -> String {
    let remote_ip = remote_addr.map(|a| a.ip());
    
    // HI-1 FIX: Only trust forwarded headers from known proxy IPs
    let trusted_proxies: Vec<IpAddr> = std::env::var("TRUSTED_PROXY_IPS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();

    let is_trusted = remote_ip.map(|ip| trusted_proxies.contains(&ip)).unwrap_or(false);

    if is_trusted {
        if let Some(xff) = headers.get("x-forwarded-for")
            && let Ok(val) = xff.to_str() {
                let ips: Vec<&str> = val.split(',').collect();
                if let Some(first) = ips.first() {
                    return first.trim().to_string();
                }
            }
        if let Some(xri) = headers.get("x-real-ip")
            && let Ok(val) = xri.to_str() {
                return val.trim().to_string();
            }
    }

    remote_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".to_string())
}


pub(crate) struct AppState {
    db: PgPool,
    jwt_secret: String,
    rate_limits: DashMap<String, Vec<Instant>>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    
    let db = db::get_db_pool().await.expect("Failed to connect to database");
    let jwt_secret = match env::var("JWT_SECRET") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("FATAL: JWT_SECRET environment variable is not set. Generate one with: openssl rand -hex 32");
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState { 
        db, 
        jwt_secret,
        rate_limits: DashMap::new(),
    });

    // Run migrations on startup
    sqlx::migrate!("./migrations").run(&state.db).await.expect("Failed to run migrations");

    let app = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
        .route("/auth/delete-account", post(delete_account))
        .route("/auth/export-data", post(export_data))
        .route("/auth/refresh", post(refresh))
        .route("/auth/recover", post(recover))
        .route("/auth/verify-google-play", post(verify_google_play))
        .route("/auth/verify-email", post(verify_email))
        .route("/keys/upload", post(upload_keys))
        .route("/keys/{client_id}", get(get_keys))
        .route("/backups/upload", post(upload_backup))
        .route("/backups/download", get(download_backup))
        .route("/health", get(|| async { Json(serde_json::json!({"status":"ok","service":"identity-server"})) }))
        .layer({
            let origins: Vec<axum::http::HeaderValue> = std::env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| "https://baton.network,tauri://localhost,http://localhost:5173".to_string())
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any)
        })
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("Identity Server running on port 3001");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn register(
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    
    // Anti-Bot Spam Rate Limiting: Max 3 registrations per IP per hour
    let ip = extract_client_ip(&headers, Some(addr));
    let now = Instant::now();
    let window = Duration::from_secs(3600);
    
    let mut attempts = state.rate_limits.entry(ip).or_insert_with(Vec::new);
    attempts.retain(|&t| now.duration_since(t) < window);
    
    if attempts.len() >= 3 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "Too many registration attempts. Please try again later.".into() }),
        ));
    }
    attempts.push(now);
    drop(attempts); // release the lock before DB query

    let password_hash = auth::hash_password(&payload.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Failed to hash password".into() }),
        )
    })?;

    let user_id = Uuid::new_v4();

    let result = sqlx::query(
        r#"
        INSERT INTO users (id, email, phone_number, password_hash, encrypted_key_backup, subscription_status, is_verified)
        VALUES ($1, $2, $3, $4, $5, 'free', false)
        "#
    )
    .bind(user_id)
    .bind(&payload.email)
    .bind(&payload.phone_number)
    .bind(&password_hash)
    .bind(&payload.encrypted_key_backup)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            let otp = {
                use rand::{rngs::OsRng, Rng};
                format!("{:06}", OsRng.gen_range(100_000..=999_999))
            };
            let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
            
            // OTP SELF-CLEANUP: Wipe expired OTPs across the whole table to prevent db bloat
            sqlx::query("DELETE FROM verification_codes WHERE expires_at < $1")
                .bind(chrono::Utc::now())
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
            
            let _ = sqlx::query("INSERT INTO verification_codes (user_id, code, expires_at) VALUES ($1, $2, $3)")
                .bind(user_id)
                .bind(&otp)
                .bind(expires_at)
                .execute(&state.db)
                .await.map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;
            
            email::send_verification_email(&payload.email, &otp).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
            
            let token = auth::generate_jwt(user_id, &state.jwt_secret).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;
            let refresh_token = auth::generate_refresh_token();
            let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
            sqlx::query("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)")
                .bind(user_id)
                .bind(&refresh_token)
                .bind(expires_at)
                .execute(&state.db)
                .await.map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;
                
            Ok(Json(AuthResponse { token, refresh_token, user_id, subscription_status: "free".to_string() }))
        }
        Err(e) => {
            eprintln!("Failed to register user: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "User already exists or invalid data".into() }),
            ))
        }
    }
}

async fn login(
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    
    // Rate Limiting Logic: Max 5 requests per 5 minutes per IP
    let ip = extract_client_ip(&headers, Some(addr));
    let now = Instant::now();
    let window = Duration::from_secs(300);
    
    let mut attempts = state.rate_limits.entry(ip).or_insert_with(Vec::new);
    attempts.retain(|&t| now.duration_since(t) < window);
    
    if attempts.len() >= 5 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "Too many login attempts. Please try again later.".into() }),
        ));
    }
    attempts.push(now);
    drop(attempts); // release the lock before DB query

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at, subscription_status, subscription_expiry, is_verified, failed_login_attempts, lockout_until FROM users WHERE email = $1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Database error".into() }),
        )
    })?;

    if let Some(user) = user {
        // Check if account is locked
        if let Some(lockout_time) = user.lockout_until
            && lockout_time > chrono::Utc::now() {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse { error: "Account locked due to too many failed attempts. Try again later.".into() }),
                ));
            }

        if !user.is_verified {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse { error: "Email not verified".into() }),
            ));
        }

        if auth::verify_password(&payload.password, &user.password_hash) {
            
            // Reset failed login attempts on success
            sqlx::query("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = $1")
                .bind(user.id)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

            // MINIMIZATION LOGIC: Self-Cleaning DB to destroy expired metadata
            sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < $1")
                .bind(chrono::Utc::now())
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
            
            // DEVICE LIMIT LOGIC
            if user.subscription_status != "premium" {
                let active_sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND is_revoked = false AND expires_at > $2")
                    .bind(user.id)
                    .bind(chrono::Utc::now())
                    .fetch_one(&state.db)
                    .await
                    .unwrap_or(0);

                if active_sessions >= 3 {
                    // Revoke the oldest session
                    sqlx::query(
                        "UPDATE refresh_tokens SET is_revoked = true WHERE id = (
                            SELECT id FROM refresh_tokens WHERE user_id = $1 AND is_revoked = false AND expires_at > $2 
                            ORDER BY created_at ASC LIMIT 1
                        )"
                    )
                    .bind(user.id)
                    .bind(chrono::Utc::now())
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
                }
            }

            let token = auth::generate_jwt(user.id, &state.jwt_secret).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;
            let refresh_token = auth::generate_refresh_token();
            let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
            sqlx::query("INSERT INTO refresh_tokens (user_id, token, expires_at, is_revoked) VALUES ($1, $2, $3, false)")
                .bind(user.id)
                .bind(&refresh_token)
                .bind(expires_at)
                .execute(&state.db)
                .await
                .map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;
                
            return Ok(Json(AuthResponse { 
                token,
                refresh_token,
                user_id: user.id, 
                subscription_status: user.subscription_status 
            }));
        } else {
            // Wrong password: increment failed attempts
            let new_attempts = user.failed_login_attempts + 1;
            if new_attempts >= 5 {
                // Lock account for 15 minutes
                let lockout_time = chrono::Utc::now() + chrono::Duration::minutes(15);
                sqlx::query("UPDATE users SET failed_login_attempts = $1, lockout_until = $2 WHERE id = $3")
                    .bind(new_attempts)
                    .bind(lockout_time)
                    .bind(user.id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
            } else {
                sqlx::query("UPDATE users SET failed_login_attempts = $1 WHERE id = $2")
                    .bind(new_attempts)
                    .bind(user.id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
            }
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse { error: "Invalid credentials".into() }),
    ))
}

async fn recover(
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<RecoverResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Rate Limiting Logic: Max 5 requests per 5 minutes per IP
    let ip = extract_client_ip(&headers, Some(addr));
    let now = Instant::now();
    let window = Duration::from_secs(300);
    
    let mut attempts = state.rate_limits.entry(ip).or_insert_with(Vec::new);
    attempts.retain(|&t| now.duration_since(t) < window);
    
    if attempts.len() >= 5 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "Too many login attempts. Please try again later.".into() }),
        ));
    }
    attempts.push(now);
    drop(attempts); // release the lock before DB query

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at, subscription_status, subscription_expiry, is_verified FROM users WHERE email = $1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Database error".into() }),
        )
    })?;

    if let Some(user) = user
        && auth::verify_password(&payload.password, &user.password_hash) {
            return Ok(Json(RecoverResponse { encrypted_key_backup: user.encrypted_key_backup }));
        }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse { error: "Invalid credentials".into() }),
    ))
}

#[derive(serde::Deserialize)]
struct ForgotPasswordRequest {
    email: String,
}

async fn forgot_password(
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // HI-5 FIX: Rate limit password reset requests (3 per IP per hour)
    let ip = format!("forgot_{}", extract_client_ip(&headers, Some(addr)));
    let now = Instant::now();
    let window = Duration::from_secs(3600);
    
    let mut attempts = state.rate_limits.entry(ip).or_insert_with(Vec::new);
    attempts.retain(|&t| now.duration_since(t) < window);
    
    if attempts.len() >= 3 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "Too many password reset attempts. Please try again later.".into() }),
        ));
    }
    attempts.push(now);
    drop(attempts);

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at, subscription_status, subscription_expiry, is_verified, failed_login_attempts, lockout_until FROM users WHERE email = $1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if let Some(user) = user {
        let otp = {
            use rand::{rngs::OsRng, Rng};
            format!("{:06}", OsRng.gen_range(100_000..=999_999))
        };
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
        
        let _ = sqlx::query("INSERT INTO verification_codes (user_id, code, expires_at) VALUES ($1, $2, $3)")
            .bind(user.id)
            .bind(&otp)
            .bind(expires_at)
            .execute(&state.db)
            .await;
        
        email::send_verification_email(&payload.email, &otp).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
    }

    Ok(Json(serde_json::json!({ "message": "If that email exists, a reset code was sent" })))
}

#[derive(serde::Deserialize)]
struct ResetPasswordRequest {
    email: String,
    code: String,
    new_password: String,
}

async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at, subscription_status, subscription_expiry, is_verified, failed_login_attempts, lockout_until FROM users WHERE email = $1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    if let Some(user) = user {
        let code_record = sqlx::query_as::<_, VerificationCodeRow>(
            "SELECT id, code, expires_at FROM verification_codes WHERE user_id = $1 AND code = $2 ORDER BY expires_at DESC LIMIT 1"
        )
        .bind(user.id)
        .bind(&payload.code)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

        if let Some(record) = code_record {
            if record.expires_at > chrono::Utc::now() {
                let password_hash = auth::hash_password(&payload.new_password).map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: "Failed to hash password".into() }),
                    )
                })?;

                sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
                    .bind(&password_hash)
                    .bind(user.id)
                    .execute(&state.db)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to update password".into() })))?;
                
                sqlx::query("DELETE FROM verification_codes WHERE user_id = $1")
                    .bind(user.id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;
                    
                sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
                    .bind(user.id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

                return Ok(Json(serde_json::json!({ "message": "Password reset successful" })));
            } else {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Code expired".into() })));
            }
        }
    }

    Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid code or email".into() })))
}

async fn verify_google_play(
    State(_state): State<Arc<AppState>>,
    axum::extract::Json(payload): axum::extract::Json<models::VerifyPlayRequest>,
) -> impl axum::response::IntoResponse {


    let client = reqwest::Client::new();
    let app_package = "com.ekam.baton";
    let url = format!(
        "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/{}/purchases/subscriptions/{}/tokens/{}",
        app_package, payload.product_id, payload.purchase_token
    );
    let google_token = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_default();
    let res = match client.get(&url)
        .bearer_auth(google_token)
        .send()
        .await {
        Ok(r) => r,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to contact Google Play API",
                "valid": false
            }))
        ),
    };

    if res.status().is_success() {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "valid": true,
                "status": "verified"
            }))
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid purchase token",
                "valid": false
            }))
        )
    }
}

#[allow(dead_code)]
#[derive(sqlx::FromRow)]
struct VerificationCodeRow {
    #[allow(dead_code)]
    id: Uuid,
    #[allow(dead_code)]
    code: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

async fn verify_email(
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<models::VerifyEmailRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    
    // Rate Limiting Logic: Max 5 requests per 5 minutes per IP
    let ip = extract_client_ip(&headers, Some(addr));
    let now = Instant::now();
    let window = Duration::from_secs(300);
    
    let mut attempts = state.rate_limits.entry(ip).or_insert_with(Vec::new);
    attempts.retain(|&t| now.duration_since(t) < window);
    
    if attempts.len() >= 5 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "Too many verification attempts. Please try again later.".into() }),
        ));
    }
    attempts.push(now);
    drop(attempts); // release the lock before DB query

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at, subscription_status, subscription_expiry, is_verified FROM users WHERE email = $1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "DB Error".into() })))?;

    if let Some(user) = user {
        let code_record = sqlx::query_as::<_, VerificationCodeRow>(
            "SELECT id, code, expires_at FROM verification_codes WHERE user_id = $1 AND code = $2 ORDER BY expires_at DESC LIMIT 1"
        )
        .bind(user.id)
        .bind(&payload.code)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "DB Error".into() })))?;

        if let Some(record) = code_record {
            if record.expires_at > chrono::Utc::now() {
                sqlx::query("UPDATE users SET is_verified = TRUE WHERE id = $1")
                    .bind(user.id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;
                
                sqlx::query("DELETE FROM verification_codes WHERE user_id = $1")
                    .bind(user.id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;
                    
                return Ok(Json(serde_json::json!({ "status": "verified" })));
            } else {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Code expired".into() })));
            }
        }
    }
    
    Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid code".into() })))
}

#[derive(sqlx::FromRow)]
struct RefreshRecord {
    user_id: Uuid,
    is_revoked: bool,
}

async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<models::RefreshRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let record = sqlx::query_as::<_, RefreshRecord>(
        "SELECT user_id, is_revoked FROM refresh_tokens WHERE token = $1 AND expires_at > $2"
    )
    .bind(&payload.refresh_token)
    .bind(chrono::Utc::now())
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "DB Error".into() })))?;

    if let Some(r) = record {
        if r.is_revoked {
            // THEFT DETECTED: This token was already used. Revoke all tokens for this user!
            sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
                .bind(r.user_id)
                .execute(&state.db)
                .await
                .map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;
            
            return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Security breach detected. All sessions revoked. Please log in again.".into() })));
        }

        // Mark the current token as revoked instead of deleting it
        sqlx::query("UPDATE refresh_tokens SET is_revoked = true WHERE token = $1")
            .bind(&payload.refresh_token)
            .execute(&state.db)
            .await
            .map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;

        let access_token = auth::generate_jwt(r.user_id, &state.jwt_secret).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;
        let new_refresh_token = auth::generate_refresh_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
        
        sqlx::query("INSERT INTO refresh_tokens (user_id, token, expires_at, is_revoked) VALUES ($1, $2, $3, false)")
            .bind(r.user_id)
            .bind(&new_refresh_token)
            .bind(expires_at)
            .execute(&state.db)
            .await
            .map_err(|e| { eprintln!("DB error: {}", e); (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Internal server error".into() })) })?;
            
        return Ok(Json(serde_json::json!({ "token": access_token, "refresh_token": new_refresh_token })));
    }
    
    
    Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid or expired refresh token".into() })))
}

async fn delete_account(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>, // Reusing LoginRequest to require email+password
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at, subscription_status, subscription_expiry, is_verified FROM users WHERE email = $1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Database error".into() }),
        )
    })?;

    if let Some(user) = user {
        // Must provide valid master password to delete
        if auth::verify_password(&payload.password, &user.password_hash) {
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(user.id)
                .execute(&state.db)
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: "Failed to delete account".into() }),
                    )
                })?;
                
            return Ok(Json(serde_json::json!({ "status": "success", "message": "Account securely wiped." })));
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse { error: "Invalid credentials".into() }),
    ))
}

async fn export_data(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>, // Require email+password
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at, subscription_status, subscription_expiry, is_verified FROM users WHERE email = $1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Database error".into() }),
        )
    })?;

    if let Some(user) = user {
        // Authenticate with master password
        if auth::verify_password(&payload.password, &user.password_hash) {
            
            // Get active session count
            let active_sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND is_revoked = false AND expires_at > $2")
                .bind(user.id)
                .bind(chrono::Utc::now())
                .fetch_one(&state.db)
                .await
                .unwrap_or(0);

            // Export payload
            let export = serde_json::json!({
                "account_info": {
                    "email": user.email,
                    "phone_number": user.phone_number,
                    "created_at": user.created_at,
                    "is_verified": user.is_verified,
                    "subscription_status": user.subscription_status,
                    "subscription_expiry": user.subscription_expiry,
                },
                "security": {
                    "encrypted_key_backup": user.encrypted_key_backup,
                    "active_sessions_count": active_sessions
                }
            });

            return Ok(Json(export));
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse { error: "Invalid credentials".into() }),
    ))
}

async fn upload_keys(
    State(state): State<Arc<AppState>>,
    user: auth::AuthenticatedUser,
    Json(payload): Json<models::UploadKeysRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let mut tx = state.db.begin().await.map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }))
    })?;

    sqlx::query(
        r#"
        INSERT INTO olm_identity_keys (client_id, identity_key, signed_pre_key, signature)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (client_id) DO UPDATE 
        SET identity_key = EXCLUDED.identity_key,
            signed_pre_key = EXCLUDED.signed_pre_key,
            signature = EXCLUDED.signature
        "#
    )
    .bind(user.id)
    .bind(&payload.identity_key)
    .bind(&payload.signed_pre_key)
    .bind(&payload.signature)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to upload identity keys".into() }))
    })?;

    if payload.one_time_keys.len() > 100 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "Maximum 100 one-time keys per upload".into() }),
        ));
    }

    for otk in payload.one_time_keys {
        sqlx::query("INSERT INTO olm_one_time_keys (client_id, key_value) VALUES ($1, $2)")
            .bind(user.id)
            .bind(otk)
            .execute(&mut *tx)
            .await
            .map_err(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to upload one time keys".into() }))
            })?;
    }

    tx.commit().await.map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to commit keys".into() }))
    })?;

    Ok(Json(serde_json::json!({ "status": "success" })))
}

async fn get_keys(
    State(state): State<Arc<AppState>>,
    user: auth::AuthenticatedUser,
    axum::extract::Path(client_id): axum::extract::Path<Uuid>,
) -> Result<Json<models::KeysResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ip_key = format!("keys_{}", user.id);
    let now = Instant::now();
    let window = Duration::from_secs(3600);
    
    let mut attempts = state.rate_limits.entry(ip_key).or_insert_with(Vec::new);
    attempts.retain(|&t| now.duration_since(t) < window);
    
    if attempts.len() >= 5 {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "Too many requests. Please try again later.".into() }),
        ));
    }
    attempts.push(now);
    drop(attempts);

    #[derive(sqlx::FromRow)]
    struct IdentityRow {
        identity_key: String,
        signed_pre_key: String,
        signature: String,
    }

    let identity = sqlx::query_as::<_, IdentityRow>(
        "SELECT identity_key, signed_pre_key, signature FROM olm_identity_keys WHERE client_id = $1"
    )
    .bind(client_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }))
    })?
    .ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Keys not found for client".into() }))
    })?;

    let otk_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM olm_one_time_keys WHERE client_id = $1"
    )
    .bind(client_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let otk: Option<String> = if otk_count > 1 {
        sqlx::query_scalar(
            r#"
            DELETE FROM olm_one_time_keys 
            WHERE key_id = (
                SELECT key_id FROM olm_one_time_keys 
                WHERE client_id = $1 
                LIMIT 1 
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_value
            "#
        )
        .bind(client_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }))
        })?
    } else {
        None
    };

    Ok(Json(models::KeysResponse {
        identity_key: identity.identity_key,
        signed_pre_key: identity.signed_pre_key,
        signature: identity.signature,
        one_time_key: otk,
    }))
}

async fn upload_backup(
    State(state): State<Arc<AppState>>,
    user: auth::AuthenticatedUser,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    const MAX_BACKUP_SIZE: usize = 50 * 1024 * 1024; // 50 MB
    if body.len() > MAX_BACKUP_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse { error: format!("Backup too large. Maximum size is {} MB", MAX_BACKUP_SIZE / 1024 / 1024) }),
        ));
    }

    let bytes = body.to_vec();
    sqlx::query(
        r#"
        INSERT INTO cloud_backups (client_id, encrypted_blob)
        VALUES ($1, $2)
        ON CONFLICT (client_id) DO UPDATE
        SET encrypted_blob = EXCLUDED.encrypted_blob,
            updated_at = CURRENT_TIMESTAMP
        "#
    )
    .bind(user.id)
    .bind(&bytes)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to upload backup".into() }))
    })?;

    Ok(Json(serde_json::json!({ "status": "success" })))
}

async fn download_backup(
    State(state): State<Arc<AppState>>,
    user: auth::AuthenticatedUser,
) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    let blob: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT encrypted_blob FROM cloud_backups WHERE client_id = $1"
    )
    .bind(user.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }))
    })?;

    match blob {
        Some(b) => Ok(b),
        None => Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "Backup not found".into() }))),
    }
}
