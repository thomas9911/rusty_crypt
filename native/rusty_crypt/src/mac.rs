use crate::error::CryptoError;
use crate::types::IoList;
use hmac::{Hmac, Mac};
use rustler::{Binary, NewBinary};
use rustler::{Env, Error, NifResult};
use sha2::digest;

use poly1305_lib::universal_hash::NewUniversalHash;
use poly1305_lib::Poly1305;

macro_rules! make_hmac {
    ($func_name:ident, $hasher:ty) => {
        #[rustler::nif]
        fn $func_name<'a>(env: Env<'a>, secret: IoList, data: IoList) -> NifResult<Binary<'a>> {
            inner_hmac::<Hmac<$hasher>>(env, secret, data)
        }
    };
}

#[rustler::nif]
fn poly1305<'a>(env: Env<'a>, secret: IoList, data: IoList) -> NifResult<Binary<'a>> {
    if secret.as_slice().len() != poly1305_lib::KEY_SIZE {
        return Err(CryptoError::BadKeyLength.to_nif_error());
    }

    let mut binary = NewBinary::new(env, poly1305_lib::BLOCK_SIZE);

    let key = poly1305_lib::Key::from_slice(secret.as_slice());

    // let mut poly = Poly1305::new(key);
    // .map_err(|_| Error::RaiseAtom("allocation_failed"))?;

    let tag = Poly1305::new(key).compute_unpadded(data.as_slice());

    binary
        .as_mut_slice()
        .copy_from_slice(tag.into_bytes().as_mut_slice());

    Ok(binary.into())
}

fn inner_hmac<'a, T>(env: Env<'a>, secret: IoList, data: IoList) -> NifResult<Binary<'a>>
where
    T: hmac::Mac
        + crypto_common::KeyInit
        + digest::Update
        + digest::FixedOutput
        + digest::MacMarker,
{
    let mut binary = NewBinary::new(env, T::output_size());

    let mut mac = <T as Mac>::new_from_slice(secret.as_slice())
        .map_err(|_| Error::RaiseAtom("allocation_failed"))?;

    Mac::update(&mut mac, data.as_slice());

    let result = mac.finalize();

    binary
        .as_mut_slice()
        .copy_from_slice(result.into_bytes().as_mut_slice());

    Ok(binary.into())
}

make_hmac!(hmac_sha2_224, sha2::Sha224);
make_hmac!(hmac_sha2_256, sha2::Sha256);
make_hmac!(hmac_sha2_384, sha2::Sha384);
make_hmac!(hmac_sha2_512, sha2::Sha512);
make_hmac!(hmac_sha3_224, sha3::Sha3_224);
make_hmac!(hmac_sha3_256, sha3::Sha3_256);
make_hmac!(hmac_sha3_384, sha3::Sha3_384);
make_hmac!(hmac_sha3_512, sha3::Sha3_512);
