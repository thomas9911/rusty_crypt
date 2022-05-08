defmodule RustyCrypt do
  @moduledoc """
  Cryptographic functions inplemented via a Rust nif.

  If you want an interface more like the erlang `:crypto` module go to `RustyCrypt.Erlang`
  """

  #   defdelegate aes256gcm_encrypt(key, data, iv, aad), to: RustyCrypt.Native
  #   defdelegate aes256gcm_decrypt(key, text, iv, aad, tag), to: RustyCrypt.Native
  #   defdelegate chacha20_poly1305_encrypt(key, data, iv, aad), to: RustyCrypt.Native
  #   defdelegate chacha20_poly1305_decrypt(key, text, iv, aad, tag), to: RustyCrypt.Native
end
