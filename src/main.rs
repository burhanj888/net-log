mod handlers;
mod middleware;
mod models;
mod utils;

use actix_web::{web, App, HttpMessage, HttpRequest, HttpServer};
use dotenv::dotenv;
use middleware::JwtMiddleware;
use sqlx::PgPool;
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to create pool.");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .route("/register", web::post().to(handlers::register_user))
            .route("/login", web::post().to(handlers::login_user))
            // Protected routes with JWT middleware
            .service(
                web::scope("") // Empty path scope to nest protected routes
                    .wrap(JwtMiddleware {
                        secret: jwt_secret.clone(),
                    })
                    .route("/protected", web::get().to(handlers::protected_route))
                    .route(
                        "/network/enable",
                        web::post().to(|req: HttpRequest, db_pool: web::Data<PgPool>| {
                            let user = req
                                .extensions()
                                .get::<String>()
                                .cloned()
                                .unwrap_or_else(|| "unknown".to_string());
                            handlers::enable_network(db_pool, user)
                        }),
                    )
                    .route(
                        "/network/disable",
                        web::post().to(|req: HttpRequest, db_pool: web::Data<PgPool>| {
                            let user = req
                                .extensions()
                                .get::<String>()
                                .cloned()
                                .unwrap_or_else(|| "unknown".to_string());
                            handlers::disable_network(db_pool, user)
                        }),
                    )
                    .route(
                        "/network/status",
                        web::get().to(handlers::get_network_status),
                    ),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
