use mongodb::{bson::doc, Collection};
use rocket::{ http::Status, outcome::Outcome, request::FromRequest, Request};

use crate::models::api_token::{self, ApiToken};

pub struct AuthenticatedClient(pub ApiToken);

#[rocket::async_trait]
impl <'r> FromRequest<'r> for AuthenticatedClient {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, (Status, ()), (Status) > {
        let token = req.headers().get_one("x-api-key");

        if token.is_none() {
            return Outcome::Error((Status::Unauthorized, ()));
        }

        let db = match req.rocket().state::<Collection<ApiToken>>() {
            Some(c) => c,
            None => return Outcome::Error((Status::Unauthorized, ()))
        };

        let token = token.unwrap();

        match db
        .find_one(doc! { "token": token, "allowed": true }, None)
        .await
         {
            Ok(Some(api_token)) => Outcome::Success(AuthenticatedClient(api_token)),
            _ => Outcome::Error((Status::Unauthorized, ()))
        }
    }
}