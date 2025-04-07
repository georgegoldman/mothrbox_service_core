
use chrono::{DateTime, Utc};
use mongodb::Collection;
use rocket::{response::status, serde::json::Json, State};
use mongodb::bson::{doc, Bson};
use mongodb::Cursor;
use futures::TryStreamExt;
use mongodb::bson::oid::ObjectId;
use rocket::http::Status;
use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use crate::models::user::User;
use crate::routes::auth::{AdminUser, AuthToken, AuthenticatedUser};
use crate::models::blacklist::BlackListedToken;


#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub email: String,

    #[serde(with = "chrono::serde::ts_seconds", default = "default_datetime")] // Serialize & Deserialize timestamps properly
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds", default = "default_datetime")]
    pub updated_at: DateTime<Utc>,
}

fn default_datetime() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
}

#[get("/profile")]
pub async fn profile(user: AuthenticatedUser, db: &State<Collection<User>>) -> Result<Json<Profile>, status::Custom<String>> {
    let result = db.find_one(doc! {"email": &user.email}).await;

    match result {
        Ok(Some(user_data)) => {
            let return_user = Profile {
                id: user_data.id,
                email: user_data.email,
                
                created_at: user_data.created_at,
                updated_at: user_data.updated_at,
                
            };
            return Ok(Json(return_user));
        },
        Ok(None) => Err(status::Custom(Status::NotFound, "User not found".to_string())), // if no user found
        Err(e) => Err(status::Custom(Status::InternalServerError, format!("Database error: {}", e)))
    }
}

#[post("/user", format="json", data="<user>")]
pub async fn sign_up(
    user: Json<RegisterRequest>, 
    db: &State<Collection<User>>
) -> Result<Json<String>, rocket::response::status::Custom<String>>
{
    // Check if the email already exists
    let filter = doc! {"email": &user.email};
    if let Ok(Some(_)) = db.find_one(filter.clone()).await {
        return Err(rocket::response::status::Custom(Status::Conflict, "User already exist".to_string()));
    }

    // hash the password
    let hashed_password = match hash(&user.password, DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(_) => return Err(rocket::response::status::Custom(Status::Conflict, "Error hashing password".to_string())),
    };

    let now = Utc::now();

    // create new user
    let new_user = User {
        id: None,
        email: user.email.clone(),
        password: hashed_password,
        admin: false,
        created_at: now,
        updated_at: now,
    };

    // Insert the new user into the database
    let result = db.insert_one(new_user).await;

    match result {
        Ok(_) => Ok(Json("User registered successfully!".to_string())),
        Err(e) => Err(rocket::response::status::Custom(Status::BadRequest, format!("Error: {e}"))),
    }

}

#[get("/users")]
pub async fn read_users(db: &State<Collection<User>>,
     _user: AuthenticatedUser,
     _token: AuthToken,
     _db_blacklist: &State<Collection<BlackListedToken>>
    ) -> Json<Vec<User>> {
    let mut cursor: Cursor<User> = db
        .find( doc! {})
        .await
        .expect("Failed to find user");
    let mut users: Vec<User> = Vec::new();
    while let Some(user) = cursor.try_next().await.expect("Error iterating cursor") {
        users.push(user);
    }
    Json(users)
}

#[get("/user/<id>")]
pub async  fn read_user(db: &State<Collection<User>>,
     id: &str, 
     _token: AuthToken,
     _user: AuthenticatedUser) -> Result<Json<User>, Status> {
    let collection = db;
    let object_id = match ObjectId::parse_str(id) {
        Ok(oid)=> oid,
        Err(_) => return Err(Status::BadRequest),
    };
    let filter = doc! {"_id": object_id};
    let result = collection.find_one(filter
        
    ).await;
    match result {
        Ok(fetched_data) => {
            if let Some(data) = fetched_data {
                Ok(Json(data))
            }else {
                Err(Status::NotFound)
            }
        }
        Err(_) => Err(Status::InternalServerError)
    }
}

#[delete("/user/<id>")]
pub async fn drop_user(id: &str, 
    db: &State<Collection<User>>,
    _token: AuthToken,
     _user: AuthenticatedUser) -> Result<Json<String>, Status> {
    let collection = db;

    let object_id = match ObjectId::parse_str(id) {
        Ok(oid) => oid,
        Err(_) => return Err(Status::BadRequest),
    };
    let filter = doc! {"_id": object_id};
    let result = collection.delete_one(filter).await;

    match result {
        Ok(delete_result) => {
            if delete_result.deleted_count > 0 {
                Ok(Json("User deleted successfully!".to_string()))
            } else {
                Err(Status::NotFound)
            }
        }
        Err(_) => Err(Status::InternalServerError),
    }
}

#[put("/user/<id>", format = "json", data="<updated_user>")]
pub async fn update_user(
    _user: AuthenticatedUser,
    id: &str,
    updated_user: Json<User>,
    _token: AuthToken,
    db: &State<Collection<User>>,
) ->  Result<Json<String>, Status> {
    let collection = db;
    let object_id = match ObjectId::parse_str(id) {
        Ok(oid) => oid,
        Err(_) => return Err(Status::BadRequest),
    };

    let updated_doc = doc! {
        "emai": updated_user.email.clone(),
    };

    let updated_doc = doc! {  "$set": Bson::Document(updated_doc)};
    
    let filter = doc! {"_id": object_id};

    match collection
        .find_one_and_update(filter, updated_doc)
        .await
    {
        Ok(Some(_)) => Ok(Json("User succesfully updated".to_string())),
        Ok(None) => {
            eprintln!("User not found: {}", id);
            Err(Status::NotFound)
        },
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            Err(Status::InternalServerError)},
    }

}

#[delete("/users")]
pub async fn delete_all_users(
    database: &State<Collection<User>>,  // Assuming you're using a `User` collection
    _admin: AdminUser, // Only admin can call this
    _token: AuthToken,  // Verify blacklisted tokens
    _user: AuthenticatedUser, // Verify authenticated user
) -> Json<String> {
    // Delete all users in the collection
    let result = database.delete_many(doc! {}).await;

    match result {
        Ok(delete_result) => {
            if delete_result.deleted_count > 0 {
                Json("All users successfully deleted.".to_string())
            } else {
                Json("No users were found to delete.".to_string())
            }
        }
        Err(_) => Json("Failed to delete users.".to_string()),
    }
}