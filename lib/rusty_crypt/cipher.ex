defmodule RustyCrypt.Cipher do
  @moduledoc """
  implemented ciphers:
  - `RustyCrypt.Cipher.Aes128gcm`
  - `RustyCrypt.Cipher.Aes192gcm`
  - `RustyCrypt.Cipher.Aes256gcm`
  - `RustyCrypt.Cipher.Aes128ccm`
  - `RustyCrypt.Cipher.Aes192ccm`
  - `RustyCrypt.Cipher.Aes256ccm`
  - `RustyCrypt.Cipher.Chacha20Poly1305`

  ## examples

  ```
  iex> alias RustyCrypt.Cipher.Aes256gcm
  ...> alias RustyCrypt.Random.Bytes
  ...> # your secret key
  ...> key = Bytes.secure_random(32)
  ...> data = "Super secret"
  ...> # if you don't have public data you can leave this empty: `<<>>`
  ...> aad = "Some data that is not secret"
  ...> # iv is not secret but should be random for each encryption
  ...> iv =  Bytes.secure_random(12)
  ...> {:ok, {encrypted, tag}} = Aes256gcm.encrypt(key, iv, data, aad)
  ...> Aes256gcm.decrypt(key, iv, encrypted, aad, tag)
  {:ok, "Super secret"}
  ```
  """
end
