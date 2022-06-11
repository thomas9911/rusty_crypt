defmodule RustyCrypt.Mac.Hmac do
  @moduledoc """
  Calculate signature of the data with the given key and algorithm.

  ```elixir
  iex> alias RustyCrypt.Mac.Hmac
  ...> alias RustyCrypt.Random.Bytes
  ...> secret = Bytes.secure_random(32)
  ...> mac = Hmac.sha2_256(secret, "my data")
  ...> byte_size(mac)
  32
  iex> secret = Bytes.secure_random(32)
  ...> mac2 = Hmac.sha2_256(secret, "my data")
  ...> mac == mac2
  false
  ```
  """

  @doc "Calculate hmac sha1"
  @spec sha1(binary, binary) :: binary
  defdelegate sha1(key, data), to: RustyCrypt.Native, as: :hmac_sha1

  @doc "Calculate hmac sha2 224"
  @spec sha2_224(binary, binary) :: binary
  defdelegate sha2_224(key, data), to: RustyCrypt.Native, as: :hmac_sha2_224
  @doc "Calculate hmac sha2 256"
  @spec sha2_256(binary, binary) :: binary
  defdelegate sha2_256(key, data), to: RustyCrypt.Native, as: :hmac_sha2_256
  @doc "Calculate hmac sha2 384"
  @spec sha2_384(binary, binary) :: binary
  defdelegate sha2_384(key, data), to: RustyCrypt.Native, as: :hmac_sha2_384
  @doc "Calculate hmac sha2 512"
  @spec sha2_512(binary, binary) :: binary
  defdelegate sha2_512(key, data), to: RustyCrypt.Native, as: :hmac_sha2_512

  @doc "Calculate hmac sha3 224"
  @spec sha3_224(binary, binary) :: binary
  defdelegate sha3_224(key, data), to: RustyCrypt.Native, as: :hmac_sha3_224
  @doc "Calculate hmac sha3 256"
  @spec sha3_256(binary, binary) :: binary
  defdelegate sha3_256(key, data), to: RustyCrypt.Native, as: :hmac_sha3_256
  @doc "Calculate hmac sha3 384"
  @spec sha3_384(binary, binary) :: binary
  defdelegate sha3_384(key, data), to: RustyCrypt.Native, as: :hmac_sha3_384
  @doc "Calculate hmac sha3 512"
  @spec sha3_512(binary, binary) :: binary
  defdelegate sha3_512(key, data), to: RustyCrypt.Native, as: :hmac_sha3_512
end
