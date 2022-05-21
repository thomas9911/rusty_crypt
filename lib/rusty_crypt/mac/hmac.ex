defmodule RustyCrypt.Mac.Hmac do
  defdelegate sha2_224(key, data), to: RustyCrypt.Native, as: :hmac_sha2_224
  defdelegate sha2_256(key, data), to: RustyCrypt.Native, as: :hmac_sha2_256
  defdelegate sha2_384(key, data), to: RustyCrypt.Native, as: :hmac_sha2_384
  defdelegate sha2_512(key, data), to: RustyCrypt.Native, as: :hmac_sha2_512
end
