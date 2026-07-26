mod auth;
mod db;
mod models;

use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use models::{AuthResponse, ErrorResponse, LoginRequest, RegisterRequest, User, RecoverResponse};
use sqlx::PgPool;
use std::env;
use std::sync::Arc;
use uuid::Uuid;

struct AppState {
    db: PgPool,
    jwt_secret: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    
    let db = db::get_db_pool().await.expect("Failed to connect to database");
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "super-secret-key-change-in-prod".to_string());

    let state = Arc::new(AppState { db, jwt_secret });

    let app = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/recover", post(recover))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("Identity Server running on port 3001");
    axum::serve(listener, app).await.unwrap();
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    let password_hash = auth::hash_password(&payload.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Failed to hash password".into() }),
        )
    })?;

    let user_id = Uuid::new_v4();

    let result = sqlx::query(
        r#"
        INSERT INTO users (id, email, phone_number, password_hash, encrypted_key_backup)
        VALUES ($1, $2, $3, $4, $5)
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
            let token = auth::generate_jwt(user_id, &state.jwt_secret).unwrap();
            Ok(Json(AuthResponse { token, user_id }))
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
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at FROM users WHERE email = $1"
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
        if auth::verify_password(&payload.password, &user.password_hash) {
            let token = auth::generate_jwt(user.id, &state.jwt_secret).unwrap();
            return Ok(Json(AuthResponse { token, user_id: user.id }));
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse { error: "Invalid credentials".into() }),
    ))
}

async fn recover(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<RecoverResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, phone_number, password_hash, encrypted_key_backup, created_at FROM users WHERE email = $1"
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
        if auth::verify_password(&payload.password, &user.password_hash) {
            return Ok(Json(RecoverResponse { encrypted_key_backup: user.encrypted_key_backup }));
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse { error: "Invalid credentials".into() }),
    ))
}
