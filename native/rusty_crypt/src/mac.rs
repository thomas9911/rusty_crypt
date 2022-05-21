use crate::types::IoList;
use hmac::{Hmac, Mac};
use rustler::{Binary, NewBinary};
use rustler::{Env, Error, NifResult};
use sha2::digest;

macro_rules! make_hmac {
    ($func_name:ident, $hasher:ty) => {
        #[rustler::nif]
        fn $func_name<'a>(env: Env<'a>, secret: IoList, data: IoList) -> NifResult<Binary<'a>> {
            inner_hmac::<Hmac<$hasher>>(env, secret, data)
        }
    };
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
