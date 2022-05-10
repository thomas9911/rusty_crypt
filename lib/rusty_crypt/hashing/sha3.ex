defmodule RustyCrypt.Hashing.Sha3 do
  @moduledoc """
  Calculate the sha3 hash of the binary with a given method

  ```elixir
  iex> RustyCrypt.Hashing.Sha3.sha256("Some data")
  <<134, 184, 100, 134, 88, 209, 99, 164, 114, 3, 199, 16, 28, 50,
    126, 184, 67, 77, 116, 26, 164, 177, 75, 27, 63, 249, 192, 139,
    167, 35, 188, 209>>
  ```
  """
  @doc "Calculate sha224 of the binary"
  defdelegate sha224(data), to: RustyCrypt.Native, as: :sha3_224
  @doc "Calculate sha256 of the binary"
  defdelegate sha256(data), to: RustyCrypt.Native, as: :sha3_256
  @doc "Calculate sha384 of the binary"
  defdelegate sha384(data), to: RustyCrypt.Native, as: :sha3_384
  @doc "Calculate sha512 of the binary"
  defdelegate sha512(data), to: RustyCrypt.Native, as: :sha3_512
end
