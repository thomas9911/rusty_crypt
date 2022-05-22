defmodule RustyCrypt.Cipher.Chacha20Poly1305 do
  @moduledoc "Use the Chacha20Poly1305 cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, iv, data, aad), to: RustyCrypt.Native, as: :chacha20_poly1305_encrypt

  @doc "Decrypt message"
  defdelegate decrypt(key, iv, data, aad, tag),
    to: RustyCrypt.Native,
    as: :chacha20_poly1305_decrypt
end
