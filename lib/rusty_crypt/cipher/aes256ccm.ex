defmodule RustyCrypt.Cipher.Aes256ccm do
  @moduledoc "Use the Aes256 ccm cipher"

  @doc "Encrypt message"
  defdelegate encrypt(key, data, iv, aad), to: RustyCrypt.Native, as: :aes256ccm_encrypt
  @doc "Decrypt message"
  defdelegate decrypt(key, text, iv, aad, tag), to: RustyCrypt.Native, as: :aes256ccm_decrypt
end
