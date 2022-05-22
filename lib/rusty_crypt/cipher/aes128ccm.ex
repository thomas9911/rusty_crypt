defmodule RustyCrypt.Cipher.Aes128ccm do
  @moduledoc "Use the Aes128 ccm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, iv, data, aad), to: RustyCrypt.Native, as: :aes128ccm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, iv, data, aad, tag), to: RustyCrypt.Native, as: :aes128ccm_decrypt
end
