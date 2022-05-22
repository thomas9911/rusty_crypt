defmodule RustyCrypt.Cipher.Aes192ccm do
  @moduledoc "Use the Aes192 ccm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, iv, data, aad), to: RustyCrypt.Native, as: :aes192ccm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, iv, data, aad, tag), to: RustyCrypt.Native, as: :aes192ccm_decrypt
end
