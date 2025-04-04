use rand::rngs::OsRng;
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

fn generate_key_pair() -> (EphemeralSecret, PublicKey) {
    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);
    (private_key, public_key)
}

fn derive_shared_secret(my_private: &EphemeralSecret, peer_public: &PublicKey) -> [u8; 32] {
    my_private.diffie_hellman(peer_public).to_bytes()
}

fn main()
{
    // generate key 
}