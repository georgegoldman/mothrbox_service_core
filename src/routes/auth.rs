use std::time::SystemTime;
use std::env;


use mongodb::bson::{doc, DateTime as BsonDateTime};
use mongodb::Collection;
use rocket::http::{HeaderMap, Status};
use rocket::serde::json::Json;
use rocket::request::{Outcome, Request, FromRequest};
use chrono::{Utc, Duration};
use hmac::Hmac;
use dotenv::dotenv;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use rocket::{post, State};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use crate::models::blacklist::BlackListedToken;

use crate::user::User;

const RANK:bool = false;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
    iat: usize,
    iss: String,
    nbf: usize,
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String
}


#[derive(Deserialize)]
struct  LoginRequest {
    email: String,
    password: String
}

lazy_static! {
    static ref REFRESH_TOKENS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

#[derive(Debug, Serialize, Deserialize)]
pub struct  RefreshRequest {
    pub refresh_token: String,
}

// add token to blacklist
lazy_static! {
    static ref BLACKLIST: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

pub async fn blacklist_token(
    token: &str, 
    db: &State<Collection<BlackListedToken>>) -> Result<(), mongodb::error::Error> {

    let blacklist_token = BlackListedToken {
        token: token.to_string(),
        blacklist_at: BsonDateTime::from(SystemTime::from(Utc::now()))
    };
    db.insert_one(blacklist_token).await?;
    Ok(())
}

pub async fn is_blacklisted(token: &str, db: &State<Collection<BlackListedToken>>) -> Result<bool, mongodb::error::Error>{
    let filter = doc! {"token": token};
    let result  = db.find_one(filter).await?;
    Ok(result.is_some())
}

// request guard for jwt
pub struct AuthenticatedUser {
    pub email: String
}

#[rocket::async_trait]
impl <'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers: &HeaderMap<'_> = req.headers();
        let auth_header = headers.get_one("Authorization");
    
        if let Some(token) = auth_header {
            if let Some(jwt) = token.strip_prefix("Bearer ") {
                // Get the MongoDB collection from Rocket's managed state
                let db = match req.rocket().state::<Collection<BlackListedToken>>() {
                    Some(db) => db,
                    None => return Outcome::Error((Status::InternalServerError, ())),
                };
    
                // Check if the token is blacklisted
                match is_blacklisted(jwt, db.into()).await {
                    Ok(true) => return Outcome::Error((Status::Unauthorized, ())), // Token is blacklisted
                    Ok(false) => (), // Token is valid
                    Err(_) => return Outcome::Error((Status::InternalServerError, ())), // Database error
                }
    
                // Validate the token
                match validate_jwt(jwt) {
                    Ok(email) => return Outcome::Success(AuthenticatedUser { email }),
                    Err(_) => return Outcome::Error((Status::Unauthorized, ())),
                }
            }
        }
        Outcome::Error((Status::Unauthorized, ()))
    }
    
}

#[derive(Debug)]
pub struct AuthToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthToken {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = req.headers();
        let auth_header = headers.get_one("Authorization");

        if let Some(token) = auth_header {
            if let Some(jwt) = token.strip_prefix("Bearer ") {
                // get the mongoDB collection from rocket's state
                let db = match req.rocket().state::<Collection<BlackListedToken>>() {
                    Some(db) => db,
                    None => return Outcome::Error((Status::InternalServerError, ())),
                };

                match validate_token(jwt, db.into()).await {
                    Ok(true) => Outcome::Success(AuthToken(jwt.to_string())), // token is valid
                    Ok(false) => Outcome::Error((Status::Unauthorized, ())),
                    Err(status) => Outcome::Error((status, ())), // unauthorized token
                }

            }else {
                Outcome::Error((Status::Unauthorized, ()))
            }
        }else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

#[derive(Debug)]
pub struct AdminUser {
    pub email: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let user_db = match req.rocket().state::<Collection<User>>() {
            Some(user_db) => user_db,
            None => return Outcome::Error((Status::InternalServerError, ())),
        };

        // Extract JWT token from Authorization header
        let auth_header = req.headers().get_one("Authorization");
        let token = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
            Some(t) => t,
            None => return Outcome::Error((Status::Unauthorized, ())),
        };

        // Decode JWT to extract email
        let email = match validate_jwt(token) {
            Ok(email) => email,
            Err(_) => return Outcome::Error((Status::Unauthorized, ())),
        };

        // Fetch user from MongoDB and check ranking
        let filter = doc! { "email": &email };
        match user_db.find_one(filter).await {
            Ok(Some(user)) if user.admin == RANK => {
                Outcome::Success(AdminUser { email })
            }   
            _ => Outcome::Error((Status::Forbidden, ())), // User is not an admin or does not exist
        }
    }
}

fn generate_jwt(addr: &str, exp_seconds: usize) -> &'static str {
    dotenv().ok();
    let secret = env::var("SECRET_KEY").expect("Secret key not set");
    let expiration = (Utc::now() + Duration::seconds(exp_seconds as i64)).timestamp(); // token valid for 2 hours
    let current_time = Utc::now().timestamp() as usize;
    let my_claim = Claims {
        sub: addr.to_owned(),
        company: "SOC".to_owned(),
        exp: expiration as usize,
        iat: current_time, // UNIX timestamp
        iss: "CxL".to_owned(),
        nbf: current_time
    };
    let encoded = encode(&Header::default(), &my_claim, &EncodingKey::from_secret(secret.as_bytes())).expect("JWT encoding failed");
    let static_encoded: &'static str = Box::leak(encoded.into_boxed_str());
    static_encoded
}

fn validate_jwt(token: &str) -> Result<String, jsonwebtoken::errors::Error> {
    dotenv().ok();
    let secret = env::var("SECRET_KEY").expect("Jwt must be set");

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default()
    )?;
    Ok(token_data.claims.sub)
}

#[post("/auth/login", format="json", data = "<credentials>")]
pub async fn login(
    credentials: Json<LoginRequest>, 
    db: &State<Collection<User>>) -> Result<Json<TokenResponse>, Status> {
    let email = credentials.email.clone();
    let password = credentials.password.clone();
    let filter  = doc! {"email": &email};
    // check if user exist
    match db.find_one(filter.clone()).await {
        Ok(Some(user)) => {
            // verify password
            if bcrypt::verify(password, &user.password).unwrap_or(false) {
                let access_token = generate_jwt(&email, 2 * 60 * 60); // expires in 2 hours
                let refresh_token = generate_jwt(&email, 7 * 24 * 60 * 60); // expire in 7 days

                // store the refresh token (in-memory Hashmap for demo)
                REFRESH_TOKENS
                .lock()
                .unwrap()
                .insert(refresh_token.to_string(), email.clone());
                Ok(Json(TokenResponse {
                    access_token: access_token.to_string(),
                    refresh_token: refresh_token.to_string()
                }))
            } else {
                Err(Status::Unauthorized)
            }
        }
        Ok(None) => Err(Status::NotFound),
        Err(e)=> {
            rocket::log::private::warn!("User not found: {}", e);
            Err(Status::InternalServerError)
        },
    }
    
}

// refresh token endpoint (post/refresh)
#[post("/refresh", format = "json", data = "<refresh_request>")]
pub fn refresh(refresh_request: Json<RefreshRequest>) -> Result<Json<TokenResponse>, Status> {
    dotenv().ok();
    let refresh_token = refresh_request.refresh_token.clone();
    let secret_key = env::var("SECRET_KEY").expect("secret must be set");
    let decoding_key: DecodingKey = DecodingKey::from_secret(secret_key.as_bytes());

    match decode::<Claims>(&refresh_token, &decoding_key, &Validation::default()) {
    Ok(token_data) => {
        let email = token_data.claims.sub;

        // Verify that the refresh token is still valid
        if let Some(_) = REFRESH_TOKENS.lock().unwrap().get(&refresh_token) {
            let new_access_token = generate_jwt(&email, 2 * 60 * 60); // grant new access for 2 hrs

            Ok(Json(TokenResponse {
                access_token: new_access_token.to_string(),
                refresh_token
            }))
        }else {
            Err(Status::Unauthorized)
        }
    }
    Err(_) => Err(Status::Unauthorized),
    }
    
}

// Logout endpoint (POST /logout)
#[post("/auth/logout", format = "json", data = "<token>")]
pub async fn loqout(token: String, db: &State<Collection<BlackListedToken>>) -> Result<Json<String>, Status> {
    match blacklist_token(&token, db).await {
        Ok(_) => Ok(Json("Token blacklisted successfully!".to_string())),
        Err(_) => Err(Status::InternalServerError)
    }
}

// before processing requests check if token is blacklisted?
pub  async fn validate_token(token: &str, db: &State<Collection<BlackListedToken>>) -> Result<bool, Status> {
    match is_blacklisted(token, db).await {
        Ok(true) => Err(Status::Unauthorized), // token is blacklisted
        Ok(false) => Ok(true),
        Err(_) => Err(Status::InternalServerError)
    }
}

