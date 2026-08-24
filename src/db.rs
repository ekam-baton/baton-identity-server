use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;

pub async fn get_db_pool() -> Result<PgPool, sqlx::Error> {
    dotenvy::dotenv().ok();
    
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/baton_identity".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(50)
        .connect(&database_url)
        .await?;

    Ok(pool)
}
