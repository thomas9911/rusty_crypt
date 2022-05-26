pub mod aead;
pub mod error;
pub mod general;
pub mod hash;
pub mod mac;
pub mod random;
pub mod types;

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
        aead::aes128gcm_decrypt,
        aead::aes192gcm_decrypt,
        aead::aes256gcm_decrypt,
        aead::aes128gcm_encrypt,
        aead::aes192gcm_encrypt,
        aead::aes256gcm_encrypt,
        aead::aes128ccm_decrypt,
        aead::aes192ccm_decrypt,
        aead::aes256ccm_decrypt,
        aead::aes128ccm_encrypt,
        aead::aes192ccm_encrypt,
        aead::aes256ccm_encrypt,
        aead::chacha20_poly1305_decrypt,
        aead::chacha20_poly1305_encrypt,
        random::secure_random_bytes,
        random::fast_random_bytes,
        general::bytes_to_integer,
        general::exor,
        general::iolist_to_binary,
        general::mod_pow,
        mac::poly1305,
        mac::hmac_sha2_224,
        mac::hmac_sha2_256,
        mac::hmac_sha2_384,
        mac::hmac_sha2_512,
        mac::hmac_sha3_224,
        mac::hmac_sha3_256,
        mac::hmac_sha3_384,
        mac::hmac_sha3_512,
    ]
);
