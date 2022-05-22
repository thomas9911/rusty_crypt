defmodule RustyCrypt.Cipher.Aes256ccm do
  @moduledoc "Use the Aes256 ccm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, iv, data, aad), to: RustyCrypt.Native, as: :aes256ccm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, iv, data, aad, tag), to: RustyCrypt.Native, as: :aes256ccm_decrypt
end
