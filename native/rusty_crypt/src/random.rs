use rand::RngCore;
use rand::distributions::{Distribution, Uniform};
use rustler::{Binary, NewBinary};
use rustler::{Env, Error, NifResult};
use crate::types::BigInt;

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

#[rustler::nif]
fn rand_uniform<'a>(low: BigInt, high: BigInt) -> NifResult<BigInt> {
    use std::cmp::PartialOrd;

    if low.ge(&high) {
        return Err(Error::BadArg)
    }

    let low: num_bigint::BigInt = low.into();
    let high: num_bigint::BigInt = high.into();
    let between = Uniform::new(low, high);

    let mut rng = rand::thread_rng();

    let bigint = between.sample(&mut rng);

    Ok(bigint.into())
}
