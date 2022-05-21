use crate::types::IoList;
use aes_gcm::aead::{AeadCore, AeadInPlace, Key, NewAead, Nonce, Tag};
use aes_gcm::aes::{Aes192, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use ccm::consts::U12;
use ccm::Ccm;
use chacha20poly1305::ChaCha20Poly1305;
use rustler::types::atom::ok;
use rustler::{Atom, Binary, NewBinary, OwnedBinary};
use rustler::{Env, Error, NifResult};
use typenum::ToInt;

type Aes256Ccm = Ccm<Aes256, U12, U12>;

#[derive(rustler::NifUnitEnum)]
enum Aes256Error {
    EncryptFailed,
    DecryptFailed,
    BadIVLength,
    BadKeyLength,
    BadTagLength,
}

type Aes192Gcm = AesGcm<Aes192, U12>;

#[rustler::nif]
fn aes128gcm_encrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    inner_aes_encrypt::<Aes128Gcm>(env, key, iv, text, aad)
}

#[rustler::nif]
fn aes192gcm_encrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    inner_aes_encrypt::<Aes192Gcm>(env, key, iv, text, aad)
}

#[rustler::nif]
fn aes256gcm_encrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    inner_aes_encrypt::<Aes256Gcm>(env, key, iv, text, aad)
}

fn inner_aes_encrypt<'a, T>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))>
where
    T: AeadCore + NewAead + AeadInPlace,
    T::NonceSize: ToInt<usize>,
    T::KeySize: ToInt<usize>,
{
    if iv.len() != <T as AeadCore>::NonceSize::to_int() {
        // 96-bits; unique per message
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }

    if key.len() != <T as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }

    let key = Key::<T>::from_slice(key.as_slice());
    let cipher = T::new(key);
    inner_encrypt(env, cipher, iv, text, aad)
}

#[rustler::nif]
fn aes256ccm_encrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
    if iv.len() != <Aes256Ccm as AeadCore>::NonceSize::to_int() {
        // 96-bits; unique per message
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }

    if key.len() != <Aes256Ccm as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }

    let key = Key::<Aes256Ccm>::from_slice(key.as_slice());
    let cipher = Aes256Ccm::new(key);
    inner_encrypt(env, cipher, iv, text, aad)
}

#[rustler::nif]
fn chacha20_poly1305_encrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
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
fn aes128gcm_decrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
    tag: IoList,
) -> NifResult<(Atom, Binary<'a>)> {
    inner_aes_decrypt::<Aes128Gcm>(env, key, iv, text, aad, tag)
}

#[rustler::nif]
fn aes192gcm_decrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
    tag: IoList,
) -> NifResult<(Atom, Binary<'a>)> {
    inner_aes_decrypt::<Aes192Gcm>(env, key, iv, text, aad, tag)
}

#[rustler::nif]
fn aes256gcm_decrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
    tag: IoList,
) -> NifResult<(Atom, Binary<'a>)> {
    inner_aes_decrypt::<Aes256Gcm>(env, key, iv, text, aad, tag)
}

fn inner_aes_decrypt<'a, T>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
    tag: IoList,
) -> NifResult<(Atom, Binary<'a>)>
where
    T: AeadCore + NewAead + AeadInPlace,
    T::NonceSize: ToInt<usize>,
    T::KeySize: ToInt<usize>,
    T::TagSize: ToInt<usize>,
{
    if iv.len() != <T as AeadCore>::NonceSize::to_int() {
        // 96-bits; unique per message
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }
    if key.len() != <T as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }
    if tag.len() != <T as AeadCore>::TagSize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadTagLength)));
    }

    let key = Key::<T>::from_slice(key.as_slice());
    let cipher = T::new(key);
    inner_decrypt(env, cipher, iv, text, aad, tag)
}

#[rustler::nif]
fn aes256ccm_decrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
    tag: IoList,
) -> NifResult<(Atom, Binary<'a>)> {
    if iv.len() != <Aes256Ccm as AeadCore>::NonceSize::to_int() {
        // 96-bits; unique per message
        return Err(Error::Term(Box::new(Aes256Error::BadIVLength)));
    }
    if key.len() != <Aes256Ccm as NewAead>::KeySize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadKeyLength)));
    }
    if tag.len() != <Aes256Ccm as AeadCore>::TagSize::to_int() {
        return Err(Error::Term(Box::new(Aes256Error::BadTagLength)));
    }

    let key = Key::<Aes256Ccm>::from_slice(key.as_slice());
    let cipher = Aes256Ccm::new(key);
    inner_decrypt(env, cipher, iv, text, aad, tag)
}

#[rustler::nif]
fn chacha20_poly1305_decrypt<'a>(
    env: Env<'a>,
    key: IoList,
    iv: IoList,
    text: IoList,
    aad: IoList,
    tag: IoList,
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

fn inner_encrypt<'a, T>(
    env: Env<'a>,
    cipher: T,
    iv: IoList,
    text: IoList,
    aad: IoList,
) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))>
where
    T: AeadCore + NewAead + AeadInPlace,
    T::NonceSize: ToInt<usize>,
    T::KeySize: ToInt<usize>,
{
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

fn inner_decrypt<'a, T>(
    env: Env<'a>,
    cipher: T,
    iv: IoList,
    text: IoList,
    aad: IoList,
    tag: IoList,
) -> NifResult<(Atom, Binary<'a>)>
where
    T: AeadCore + NewAead + AeadInPlace,
    T::NonceSize: ToInt<usize>,
    T::KeySize: ToInt<usize>,
    T::TagSize: ToInt<usize>,
{
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
