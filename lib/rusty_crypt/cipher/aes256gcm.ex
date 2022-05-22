defmodule RustyCrypt.Cipher.Aes256gcm do
  @moduledoc "Use the Aes256 gcm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, iv, data, aad), to: RustyCrypt.Native, as: :aes256gcm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, iv, data, aad, tag), to: RustyCrypt.Native, as: :aes256gcm_decrypt
end
