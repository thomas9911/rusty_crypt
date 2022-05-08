defmodule RustyCrypt.Cipher.Chacha20Poly1305 do
  @moduledoc "Use the Chacha20Poly1305 cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, data, iv, aad), to: RustyCrypt.Native, as: :chacha20_poly1305_encrypt

  @doc "Decrypt message"
  defdelegate decrypt(key, text, iv, aad, tag),
    to: RustyCrypt.Native,
    as: :chacha20_poly1305_decrypt
end
