use mongodb::{bson::oid::ObjectId, Collection};
use rocket::{data::ToByteUnit, State};
use tokio::io::AsyncReadExt;

use crate::model_core::key::KeyPair;





pub struct CipherBlock;

impl CipherBlock {

    async fn cipher_texting(&self, db: &State<Collection<KeyPair>>, data: rocket::Data<'_>, user_id: &str,  alias: &str) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut stream = data.open(5.megabytes());
        stream.read_to_end(&mut buffer).await;

        // todo check if the objectId id correct
        let user = match ObjectId::parse_str(user_id.clone()) {
            Ok(oid) => oid,
            Err(e) => {
                eprintln!("Invalid user ID: {}", e);
                return b"invalid user Id".to_vec();
            }
        };
        // todo get private key from db
        let filter = mongodb::bson::doc! {"alias": alias};
        
        // if let Ok(Some(keypair)) = db.find_one(filter.clone(), None).await {
        //     return b"Alias doesn't exist".to_vec();
        // }
        // todo get iv

        // todo encrypt the file 

        buffer
    }

    pub async fn call_cipherer(&self, db: &State<Collection<KeyPair>>, data: rocket::Data<'_>, user_id: &str, alias: &str) -> Vec<u8>{
        self.cipher_texting(db, data, user_id, alias).await
    }
}