pub mod aead;
pub mod general;
pub mod hash;
pub mod random;

rustler::init!(
    "Elixir.RustyCrypt.Native",
    [
        hash::sha224,
        hash::sha256,
        hash::sha384,
        hash::sha512,
        hash::sha3_224,
        hash::sha3_256,
        hash::sha3_384,
        hash::sha3_512,
        aead::aes256gcm_decrypt,
        aead::aes256gcm_encrypt,
        aead::aes256ccm_decrypt,
        aead::aes256ccm_encrypt,
        aead::chacha20_poly1305_decrypt,
        aead::chacha20_poly1305_encrypt,
        random::secure_random_bytes,
        random::fast_random_bytes,
        general::bytes_to_integer
    ]
);
