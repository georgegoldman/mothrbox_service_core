use mongodb::{Client, Collection};
use std::sync::Arc;
use dotenv::dotenv;
use std::env;

pub async fn connect<T>() -> Collection<T>

where 
T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Unpin + 'static,
{
    dotenv().ok();
    let client  = Client::with_uri_str(env::var("DATABASE_URL").expect("Database connection not set"))
    .await
    .expect("failed to connect to mongodb");

    let db = client.database("mothrbox");
    println!("DB connected successfully");
    db.collection(std::any::type_name::<T>().split("::").last().unwrap())
}