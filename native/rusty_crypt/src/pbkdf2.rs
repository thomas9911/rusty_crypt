use hmac::Hmac;
use password_hash::Output;
use rustler::{Binary, Env, Error, NewBinary, NifResult};
use sha1::Sha1;
use sha2::digest::{FixedOutput, KeyInit, Update};
use sha2::{Sha224, Sha256, Sha384, Sha512};

macro_rules! make_pdkf2 {
    ($name: ident, $algo: ty) => {
        #[rustler::nif]
        fn $name<'a>(
            env: Env<'a>,
            password: Binary<'a>,
            salt: Binary<'a>,
            iter: u32,
            out_size: usize,
        ) -> NifResult<Binary<'a>> {
            inner::<$algo>(env, &password, &salt, iter, out_size)
        }
    };
}

make_pdkf2!(pbkdf2_sha1, Hmac<Sha1>);
make_pdkf2!(pbkdf2_sha224, Hmac<Sha224>);
make_pdkf2!(pbkdf2_sha256, Hmac<Sha256>);
make_pdkf2!(pbkdf2_sha384, Hmac<Sha384>);
make_pdkf2!(pbkdf2_sha512, Hmac<Sha512>);

fn inner<'a, T: KeyInit + Update + FixedOutput + Clone + Sync>(
    env: Env<'a>,
    password: &[u8],
    salt: &[u8],
    iter: u32,
    out_size: usize,
) -> NifResult<Binary<'a>> {
    let output = Output::init_with(out_size, |out| {
        pbkdf2::pbkdf2::<T>(password, salt, iter, out);
        Ok(())
    })
    .map_err(to_error)?;

    let mut binary = NewBinary::new(env, out_size);

    binary.as_mut_slice().copy_from_slice(output.as_bytes());

    Ok(binary.into())
}

fn to_error(error: password_hash::Error) -> Error {
    match error {
        _ => Error::RaiseAtom("pbkdf2_failed"),
    }
}
