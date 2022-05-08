defmodule RustyCrypt.Cipher.Aes256gcm do
  @moduledoc "Use the Aes256 gcm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, data, iv, aad), to: RustyCrypt.Native, as: :aes256gcm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, text, iv, aad, tag), to: RustyCrypt.Native, as: :aes256gcm_decrypt
end
