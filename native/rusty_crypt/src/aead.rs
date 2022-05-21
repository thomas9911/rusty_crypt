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

macro_rules! make_encrypt {
    ($func_name:ident, $cipher:ty) => {
        #[rustler::nif]
        fn $func_name<'a>(
            env: Env<'a>,
            key: IoList,
            iv: IoList,
            text: IoList,
            aad: IoList,
        ) -> NifResult<(Atom, (Binary<'a>, Binary<'a>))> {
            inner_encrypt::<$cipher>(env, key, iv, text, aad)
        }
    };
}

macro_rules! make_decrypt {
    ($func_name:ident, $cipher:ty) => {
        #[rustler::nif]
        fn $func_name<'a>(
            env: Env<'a>,
            key: IoList,
            iv: IoList,
            text: IoList,
            aad: IoList,
            tag: IoList,
        ) -> NifResult<(Atom, Binary<'a>)> {
            inner_decrypt::<$cipher>(env, key, iv, text, aad, tag)
        }
    };
}

make_encrypt!(aes128gcm_encrypt, Aes128Gcm);
make_encrypt!(aes192gcm_encrypt, Aes192Gcm);
make_encrypt!(aes256gcm_encrypt, Aes256Gcm);
make_encrypt!(aes256ccm_encrypt, Aes256Ccm);
make_encrypt!(chacha20_poly1305_encrypt, ChaCha20Poly1305);

make_decrypt!(aes128gcm_decrypt, Aes128Gcm);
make_decrypt!(aes192gcm_decrypt, Aes192Gcm);
make_decrypt!(aes256gcm_decrypt, Aes256Gcm);
make_decrypt!(aes256ccm_decrypt, Aes256Ccm);
make_decrypt!(chacha20_poly1305_decrypt, ChaCha20Poly1305);

fn inner_encrypt<'a, T>(
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
