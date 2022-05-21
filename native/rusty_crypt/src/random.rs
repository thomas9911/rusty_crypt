use rand::RngCore;
use rustler::{Binary, NewBinary};
use rustler::{Env, Error, NifResult};

#[rustler::nif]
fn secure_random_bytes<'a>(env: Env<'a>, bytes: usize) -> NifResult<Binary<'a>> {
    let mut binary = NewBinary::new(env, bytes);

    rand::thread_rng()
        .try_fill_bytes(binary.as_mut_slice())
        .map_err(|e| Error::RaiseTerm(Box::new(e.to_string())))?;

    Ok(binary.into())
}

#[rustler::nif]
fn fast_random_bytes<'a>(env: Env<'a>, bytes: usize) -> NifResult<Binary<'a>> {
    use rand::SeedableRng;

    let mut binary = NewBinary::new(env, bytes);

    rand::rngs::SmallRng::from_entropy()
        .try_fill_bytes(binary.as_mut_slice())
        .map_err(|e| Error::RaiseTerm(Box::new(e.to_string())))?;

    Ok(binary.into())
}
