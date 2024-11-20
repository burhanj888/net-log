use actix_web::{web, HttpResponse, Responder};
use sqlx::PgPool;
use serde::Deserialize;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use crate::utils::create_jwt;
use std::env;
use crate::models::NetworkAction;

#[derive(Deserialize)]
pub struct RegisterUser {
    username: String,
    email: String,
    password: String,
}

pub async fn register_user(
    db_pool: web::Data<PgPool>,
    form: web::Json<RegisterUser>,
) -> impl Responder {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();


    let result = sqlx::query!(
        "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
        form.username,
        form.email,
        password_hash
    )
    .execute(db_pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("User registered successfully!"),
        Err(_) => HttpResponse::InternalServerError().body("Failed to register user"),
    }
}


#[derive(Deserialize)]
pub struct LoginUser {
    username: String,
    password: String,
}

pub async fn login_user(
    db_pool: web::Data<PgPool>,
    form: web::Json<LoginUser>,
) -> impl Responder {
    let user = sqlx::query!(
        "SELECT * FROM users WHERE username = $1",
        form.username
    )
    .fetch_one(db_pool.get_ref())
    .await;

    match user {
        Ok(record) => {
            let argon2 = Argon2::default();
            let parsed_hash = PasswordHash::new(&record.password_hash).unwrap();
            let password_match = argon2
                .verify_password(form.password.as_bytes(), &parsed_hash)
                .is_ok();


            if password_match {
                let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                let token = create_jwt(&form.username, &secret);
                HttpResponse::Ok().json(serde_json::json!({ "token": token }))
            } else {
                HttpResponse::Unauthorized().body("Invalid credentials")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("Invalid credentials"),
    }
}

pub async fn protected_route() -> impl Responder {
    HttpResponse::Ok().body("Access granted to protected route!")
}

// Simulate enabling network access and log to the database
pub async fn enable_network(db_pool: web::Data<PgPool>, user: String) -> impl Responder {
    let action = "enable";
    if let Err(_) = sqlx::query!(
        "INSERT INTO network_actions (action, performed_by) VALUES ($1, $2)",
        action,
        user
    )
    .execute(db_pool.get_ref())
    .await
    {
        return HttpResponse::InternalServerError().body("Failed to log network action");
    }
    HttpResponse::Ok().body("Network access enabled and action logged.")
}

// Simulate disabling network access and log to the database
pub async fn disable_network(db_pool: web::Data<PgPool>, user: String) -> impl Responder {
    let action = "disable";
    if let Err(_) = sqlx::query!(
        "INSERT INTO network_actions (action, performed_by) VALUES ($1, $2)",
        action,
        user
    )
    .execute(db_pool.get_ref())
    .await
    {
        return HttpResponse::InternalServerError().body("Failed to log network action");
    }
    HttpResponse::Ok().body("Network access disabled and action logged.")
}

// Retrieve network status and list of actions
pub async fn get_network_status(db_pool: web::Data<PgPool>) -> impl Responder {
    match sqlx::query_as::<_, NetworkAction>("SELECT * FROM network_actions ORDER BY timestamp DESC")
        .fetch_all(db_pool.get_ref())
        .await
    {
        Ok(actions) => HttpResponse::Ok().json(actions),
        Err(_) => HttpResponse::InternalServerError().body("Failed to fetch network actions"),
    }
}
