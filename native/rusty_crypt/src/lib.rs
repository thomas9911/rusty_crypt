use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use rustler::{Atom, Binary, NewBinary, OwnedBinary};
use rustler::{Env, Error, NifResult};
use rustler::types::atom::ok;
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(rustler::NifUnitEnum)]
enum Aes256Error {
    EncryptFailed,
    DecryptFailed,
    BadIVLength,
    BadKeyLength,
    BadTagLength,
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
fn aes256gcm_encrypt<'a>(
    env: Env<'a>,
    key: Binary,
    iv: Binary,
    text: Binary,
    aad: Binary,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    if iv.len() != 12 {
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }
    if key.len() != 32 {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }

    let key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(key);
    let mut text = OwnedBinary::from_unowned(&text).unwrap();

    let nonce = Nonce::from_slice(iv.as_slice()); // 96-bits; unique per message

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad.as_slice(), &mut text.as_mut_slice())
        .map_err(|_| Error::Term(Box::new(Aes256Error::EncryptFailed)))?;

    let mut tag_binary = NewBinary::new(env, tag.len());
    tag_binary.as_mut_slice().copy_from_slice(tag.as_slice());
    Ok((ok(), (Binary::from_owned(text, env), Binary::from(tag_binary))))
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
    if iv.len() != 12 {
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }
    if key.len() != 32 {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }
    if tag.len() != 16 {
        return Err(Error::Term(Box::new(Aes256Error::BadTagLength)));
    }

    let key = Key::from_slice(key.as_slice());
    let cipher = Aes256Gcm::new(key);
    let mut text = OwnedBinary::from_unowned(&text).unwrap();

    let nonce = Nonce::from_slice(iv.as_slice()); // 96-bits; unique per message
    let tag = Tag::from_slice(tag.as_slice());

    cipher
        .decrypt_in_place_detached(nonce, aad.as_slice(), &mut text.as_mut_slice(), tag)
        .map_err(|_| Error::Term(Box::new(Aes256Error::DecryptFailed)))?;

    let mut tag_binary = NewBinary::new(env, tag.len());
    tag_binary.as_mut_slice().copy_from_slice(tag.as_slice());
    Ok((ok(), Binary::from_owned(text, env)))
}

rustler::init!(
    "Elixir.RustyCrypt",
    [sha256, aes256gcm_decrypt, aes256gcm_encrypt]
);
