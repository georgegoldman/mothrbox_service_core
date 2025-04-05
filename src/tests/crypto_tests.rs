// src/tests/crypto_tests.rs

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdh::EphemeralSecret;
    use p256::PublicKey;
    use crate::crypto::ecc::ECCrypto;

    #[test]
    fn test_encryption_and_decryption() {
        let secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
        let pub_key = PublicKey::from(&secret);

        let encrypted = ECCrypto::encrypt(b"hello", &pub_key).unwrap();
        let decrypted = ECCrypto::decrypt(&secret, &encrypted.ephemeral_public_key, &encrypted.ciphertext).unwrap();

        assert_eq!(decrypted, b"hello");
    }
}
