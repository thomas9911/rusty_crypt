use aes_gcm::aead::{AeadCore, AeadInPlace, NewAead};
// use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use aes_gcm::aead::{Nonce, Tag, Key};
use aes_gcm::{Aes256Gcm};

use chacha20poly1305::ChaCha20Poly1305;

use rustler::types::atom::ok;
use rustler::{Atom, Binary, NewBinary, OwnedBinary};
use rustler::{Env, Error, NifResult};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::io::Write;
use typenum::ToInt;

#[derive(rustler::NifUnitEnum)]
enum Aes256Error {
    EncryptFailed,
    DecryptFailed,
    BadIVLength,
    BadKeyLength,
    BadTagLength,
}

#[rustler::nif]
fn sha224<'a>(env: Env<'a>, data: Binary) -> Binary<'a> {
    let mut binary = NewBinary::new(env, Sha224::output_size());
    binary
        .as_mut_slice()
        .write_all(&Sha224::digest(data.as_slice()))
        .unwrap();
    binary.into()
}


#[rustler::nif]
fn sha256<'a>(env: Env<'a>, data: Binary) -> Binary<'a> {
    let mut binary = NewBinary::new(env, Sha256::output_size());
    binary
        .as_mut_slice()
        .write_all(&Sha256::digest(data.as_slice()))
        .unwrap();
    binary.into()
}

#[rustler::nif]
fn sha384<'a>(env: Env<'a>, data: Binary) -> Binary<'a> {
    let mut binary = NewBinary::new(env, Sha384::output_size());
    binary
        .as_mut_slice()
        .write_all(&Sha384::digest(data.as_slice()))
        .unwrap();
    binary.into()
}

#[rustler::nif]
fn sha512<'a>(env: Env<'a>, data: Binary) -> Binary<'a> {
    let mut binary = NewBinary::new(env, Sha512::output_size());
    binary
        .as_mut_slice()
        .write_all(&Sha512::digest(data.as_slice()))
        .unwrap();
    binary.into()
}

#[rustler::nif]
fn aes256gcm_encrypt<'a>(
    env: Env<'a>,
    key: Binary,
    iv: Binary,
    text: Binary,
    aad: Binary,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    if iv.len() != <Aes256Gcm as AeadCore>::NonceSize::to_int() {
        // 96-bits; unique per message
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }

    if key.len() != <Aes256Gcm as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }

    let key = Key::<Aes256Gcm>::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(key);
    inner_encrypt(env, cipher, iv, text, aad)
}

#[rustler::nif]
fn chacha20_poly1305_encrypt<'a>(
    env: Env<'a>,
    key: Binary,
    iv: Binary,
    text: Binary,
    aad: Binary,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    if iv.len() != <ChaCha20Poly1305 as AeadCore>::NonceSize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }

    if key.len() != <ChaCha20Poly1305 as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }

    let key = Key::<ChaCha20Poly1305>::from_slice(key.as_slice());
    let cipher = ChaCha20Poly1305::new(key);
    inner_encrypt(env, cipher, iv, text, aad)
}

#[rustler::nif]
fn aes256gcm_decrypt<'a>(
    env: Env<'a>,
    key: Binary,
    iv: Binary,
    text: Binary,
    aad: Binary,
    tag: Binary,
) -> NifResult<(Atom, Binary<'a>)> {
    if iv.len() != <Aes256Gcm as AeadCore>::NonceSize::to_int() {
        // 96-bits; unique per message
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }
    if key.len() != <Aes256Gcm as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }
    if tag.len() != <Aes256Gcm as AeadCore>::TagSize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadTagLength)));
    }

    let key = Key::<Aes256Gcm>::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(key);
    inner_decrypt(env, cipher, iv, text, aad, tag)
}

#[rustler::nif]
fn chacha20_poly1305_decrypt<'a>(
    env: Env<'a>,
    key: Binary,
    iv: Binary,
    text: Binary,
    aad: Binary,
    tag: Binary,
) -> NifResult<(Atom, Binary<'a>)> {
    if iv.len() != <ChaCha20Poly1305 as AeadCore>::NonceSize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }
    if key.len() != <ChaCha20Poly1305 as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }
    if tag.len() != <ChaCha20Poly1305 as AeadCore>::TagSize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadTagLength)));
    }

    let key = Key::<ChaCha20Poly1305>::from_slice(key.as_slice());
    let cipher = ChaCha20Poly1305::new(key);
    inner_decrypt(env, cipher, iv, text, aad, tag)
}

fn inner_encrypt<'a, T: AeadInPlace>(
    env: Env<'a>,
    cipher: T,
    iv: Binary,
    text: Binary,
    aad: Binary,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    let mut text = OwnedBinary::from_unowned(&text).unwrap();

    let nonce = Nonce::<T>::from_slice(iv.as_slice());

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad.as_slice(), &mut text.as_mut_slice())
        .map_err(|_| Error::Term(Box::new(Aes256Error::EncryptFailed)))?;

    let mut tag_binary = NewBinary::new(env, tag.len());
    tag_binary.as_mut_slice().copy_from_slice(tag.as_slice());
    Ok((
        ok(),
        (Binary::from_owned(text, env), Binary::from(tag_binary)),
    ))
}

fn inner_decrypt<'a, T: AeadInPlace>(
    env: Env<'a>,
    cipher: T,
    iv: Binary,
    text: Binary,
    aad: Binary,
    tag: Binary,
) -> NifResult<(Atom, Binary<'a>)> {
    let mut text = OwnedBinary::from_unowned(&text).unwrap();

    let nonce = Nonce::<T>::from_slice(iv.as_slice()); // 96-bits; unique per message
    let tag = Tag::<T>::from_slice(tag.as_slice());

    cipher
        .decrypt_in_place_detached(nonce, aad.as_slice(), &mut text.as_mut_slice(), tag)
        .map_err(|_| Error::Term(Box::new(Aes256Error::DecryptFailed)))?;

    let mut tag_binary = NewBinary::new(env, tag.len());
    tag_binary.as_mut_slice().copy_from_slice(tag.as_slice());
    Ok((ok(), Binary::from_owned(text, env)))
}

rustler::init!(
    "Elixir.RustyCrypt",
    [sha224, sha256, sha384, sha512, aes256gcm_decrypt, aes256gcm_encrypt, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt]
);
