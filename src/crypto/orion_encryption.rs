

use orion::hazardous::{mac::poly1305::POLY1305_OUTSIZE, stream::chacha20::CHACHA_KEYSIZE};
use rand::{rngs::OsRng, RngCore};
use orion::hazardous::aead::xchacha20poly1305::{SecretKey, Nonce, seal};
use orion::kdf::{derive_key, Password, Salt};
use std::io::{Write, Result as IoResult};

pub fn get_random(dest: &mut [u8]) {
    RngCore::fill_bytes(&mut OsRng, dest);
}

pub fn nonce()-> Vec<u8> {
    let mut randoms: [u8; 24] = [0; 24];
    get_random(&mut randoms);
    randoms.to_vec()
}

fn auth_tag() -> Vec<u8> {
    let mut randoms: [u8; 32] = [0; 32];
    get_random(&mut randoms);
    randoms.to_vec()
}

fn simple_split_encrypted(cipher_text: &[u8]) -> (Vec<u8>, Vec<u8>) {
    return (
        cipher_text[..CHACHA_KEYSIZE].to_vec(),
        cipher_text[CHACHA_KEYSIZE..].to_vec(),
    )
}

pub fn create_key(password: String, nonce: Vec<u8>) -> SecretKey {
    let password = Password::from_slice(password.as_bytes()).unwrap();
    let salt  = Salt::from_slice(nonce.as_slice()).unwrap();
    let kdf_key = derive_key(&password, &salt, 15, 1024, CHACHA_KEYSIZE as u32).unwrap();
    let key = SecretKey::from_slice(kdf_key.unprotected_as_bytes()).unwrap();
    key
}

pub fn encrypt_core<W: Write>(
    mut dist: W,
    contents: &[u8],
    key: &SecretKey,
    nonce: Nonce
) -> IoResult<()> {
    let ad = auth_tag();
    let output_len = contents.len()
    .checked_add(POLY1305_OUTSIZE + ad.len())
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "plaintext too long"))?;

    let mut output = vec![0u8; output_len];
    output[..CHACHA_KEYSIZE].copy_from_slice(ad.as_ref());

    seal(key, &nonce, contents, Some(ad.as_slice()), &mut output[CHACHA_KEYSIZE..]).unwrap();

    dist.write_all(&output)?;

    Ok(())
}