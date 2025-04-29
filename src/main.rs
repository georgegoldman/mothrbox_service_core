use actix_web::{App, HttpServer, middleware::{Logger, Compress}};
use actix_web::web;
use actix_cors::Cors;
mod crypto;
mod routes;

pub fn configure_app(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(routes::health_check)
            .service(routes::generate_key_pair_handler)
            .service(routes::generate_shared_secret_handler)
            .service(routes::get_recipient_public_key_handler)
            .service(routes::encrypt_file_handler)
            .service(routes::decrypt_file_handler)
    );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize the logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    println!("Starting cryptographic service on 127.0.0.1:8080");
    
    HttpServer::new(|| {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec!["Content-Type", "Authorization"])
            .max_age(3600);
            
        App::new()
            .wrap(Logger::default())
            .wrap(Compress::default())
            .wrap(cors)
            .configure(configure_app)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}