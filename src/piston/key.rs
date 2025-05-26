
use futures::stream;
use mongodb::{bson::oid::{self, ObjectId}, Collection};
use crate::encryption_core::openssl_ecc_key_gen::OpensslEccKeyGen;
use rocket::{data::ToByteUnit, serde::json::Json, State};
use tokio::io::AsyncReadExt;


use crate::{dto::GenerateKeypairRequest, model_core::key::KeyPair};
use aes::Aes128;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub struct KeyService;

impl KeyService {
    pub async fn create_key(&self, 
        db: &State<Collection<KeyPair>>,
        key_pair: Json<GenerateKeypairRequest>
    ) 
    -> Result<Json<String>, rocket::response::status::Custom<String>>
    {
        let filter = mongodb::bson::doc! {"alias": &key_pair.alias};
        
        if let Ok(Some(_)) = db.find_one(filter.clone(), None).await {
            return Err(rocket::response::status::Custom(rocket::http::Status::Conflict, "Alias exist".to_string()));
        }
        
        let now = mongodb::bson::DateTime::now();
        let key_engine = OpensslEccKeyGen{};
        let value = key_engine.get_key();

        let owner_id = match ObjectId::parse_str(key_pair.owner.clone()) {
            Ok(oid) => oid,
            Err(e) => return Err(rocket::response::status::Custom(rocket::http::Status::InternalServerError, format!("Database error: {}", e)))
        };

        let new_key = KeyPair {
            id: None,
            owner: owner_id,
            algorithm: Some(key_pair.algorithm.clone()),
            alias: key_pair.alias.clone(),
            value: value.to_vec() ,
            is_active: true,
            created_at: Some(now),
            updated_at: Some(now)
        };


        let result  = db.insert_one(new_key, None).await;

        match result {
            Ok(_) => Ok(Json("key pair read in to storage".to_string())),
            Err(e) => Err(rocket::response::status::Custom(
                rocket::http::Status::BadRequest,
                format!("Error: {e}")
            ))
        }


        
    }
}

pub struct EcryptionService;

impl EcryptionService {
    pub async fn decrypt(
        &self,
        db: &State<Collection<KeyPair>>,
        alias: &str,
        user_id: &str,
        data: rocket::Data<'_>
    ) -> Vec<u8>{
        let mut buffer = Vec::new();
        let mut stream = data.open(5.megabytes());
        stream.read_to_end(&mut buffer).await;

        let user = match ObjectId::parse_str(user_id.clone()) {
         Ok(oid) => oid,
         Err(e) => {
            eprintln!("Invalid user id: {}", e);
                return b"invalid user id".to_vec();
            }
        };

        let filter = mongodb::bson::doc! {"alias": alias};

        let keypair = match db.find_one(filter, None).await {
            Ok(Some(keypair)) => keypair,
            Ok(None) => return b"this is data doesn't exist on the db".to_vec(),
            Err(e)=> return b"there is an issue trying to run some operation on the database".to_vec()
        };

        let openssl_instance = OpensslEccKeyGen{};
        let iv = openssl_instance.get_iv();

        let cipher: Cbc<Aes128, Pkcs7> = Aes128Cbc::new_from_slices(&keypair.value, &iv).unwrap();

        let decrypted_text = cipher.decrypt_vec(&buffer).unwrap();

        decrypted_text


    }

    pub async fn encrypt(
        &self,
        db: &State<Collection<KeyPair>>,
        alias: &str,
        user_id: &str,
        data: rocket::Data<'_>
    ) -> Vec<u8>
    {
     let mut buffer = Vec::new();
     let mut stream = data.open(5.megabytes());
     stream.read_to_end(&mut buffer).await;

     let user = match ObjectId::parse_str(user_id.clone()) {
         Ok(oid) => oid,
         Err(e) => {
            eprintln!("Invalid user id: {}", e);
            return b"invalid user id".to_vec();
         }
     };
     let filter = mongodb::bson::doc! {"alias": alias};

     let keypair = match db.find_one(filter, None).await {
        Ok(Some(keypair)) => keypair,
        Ok(None) => return b"this is data doesn't exist on the db".to_vec(),
        Err(e)=> return b"there is an issue trying to run some operation on the database".to_vec()
     };

    let openssl_instance = OpensslEccKeyGen{};
    let iv = openssl_instance.get_iv();

    let cipher: Cbc<Aes128, Pkcs7> = Aes128Cbc::new_from_slices(&keypair.value, &iv).unwrap();

    let ciphertext = cipher.encrypt_vec(&buffer);

    ciphertext
     
    }
}