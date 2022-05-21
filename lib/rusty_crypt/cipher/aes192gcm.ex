defmodule RustyCrypt.Cipher.Aes192gcm do
  @moduledoc "Use the Aes192 gcm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, data, iv, aad), to: RustyCrypt.Native, as: :aes192gcm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, text, iv, aad, tag), to: RustyCrypt.Native, as: :aes192gcm_decrypt
end
