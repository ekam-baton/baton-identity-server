use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
    Ok(password_hash)
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

pub fn generate_jwt(user_id: Uuid, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize + 60 * 15; // 15 minutes

    let claims = Claims {
        sub: user_id,
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

pub fn generate_refresh_token() -> String {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    hex::encode(key)
}

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

pub struct AuthenticatedUser {
    pub id: Uuid,
}

impl FromRequestParts<std::sync::Arc<crate::AppState>> for AuthenticatedUser {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &std::sync::Arc<crate::AppState>) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));


        let token = match auth_header {
            Some(token) => token,
            None => return Err((StatusCode::UNAUTHORIZED, "Missing or invalid authorization header".to_string())),
        };

        let secret = &state.jwt_secret;
        
        let token_data = match jsonwebtoken::decode::<Claims>(token, &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()), &jsonwebtoken::Validation::default()) {
            Ok(data) => data,
            Err(_) => return Err((StatusCode::UNAUTHORIZED, "Invalid token".to_string())),
        };

        Ok(AuthenticatedUser { id: token_data.claims.sub })
    }
}
