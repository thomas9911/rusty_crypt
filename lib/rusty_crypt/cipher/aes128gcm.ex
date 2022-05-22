defmodule RustyCrypt.Cipher.Aes128gcm do
  @moduledoc "Use the Aes128 gcm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, iv, data, aad), to: RustyCrypt.Native, as: :aes128gcm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, iv, data, aad, tag), to: RustyCrypt.Native, as: :aes128gcm_decrypt
end
