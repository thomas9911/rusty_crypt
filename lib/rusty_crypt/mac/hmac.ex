defmodule RustyCrypt.Mac.Hmac do
  @moduledoc """
  Calculate signature of the data with the given key and algorithm.
  """

  @doc "Calculate hmac sha2 224"
  defdelegate sha2_224(key, data), to: RustyCrypt.Native, as: :hmac_sha2_224
  @doc "Calculate hmac sha2 256"
  defdelegate sha2_256(key, data), to: RustyCrypt.Native, as: :hmac_sha2_256
  @doc "Calculate hmac sha2 384"
  defdelegate sha2_384(key, data), to: RustyCrypt.Native, as: :hmac_sha2_384
  @doc "Calculate hmac sha2 512"
  defdelegate sha2_512(key, data), to: RustyCrypt.Native, as: :hmac_sha2_512

  @doc "Calculate hmac sha3 224"
  defdelegate sha3_224(key, data), to: RustyCrypt.Native, as: :hmac_sha3_224
  @doc "Calculate hmac sha3 256"
  defdelegate sha3_256(key, data), to: RustyCrypt.Native, as: :hmac_sha3_256
  @doc "Calculate hmac sha3 384"
  defdelegate sha3_384(key, data), to: RustyCrypt.Native, as: :hmac_sha3_384
  @doc "Calculate hmac sha3 512"
  defdelegate sha3_512(key, data), to: RustyCrypt.Native, as: :hmac_sha3_512
end
