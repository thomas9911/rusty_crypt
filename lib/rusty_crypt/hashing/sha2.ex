defmodule RustyCrypt.Hashing.Sha2 do
  @moduledoc """
  Calculate the sha2 hash of the binary with a given method

  ```elixir
  iex> RustyCrypt.Hashing.Sha2.sha256("Some data")
  <<31, 230, 56, 180, 120, 248, 240, 178, 194, 170, 179, 219, 253,
    63, 5, 214, 223, 226, 25, 28, 215, 180, 72, 34, 65, 254, 88, 86,
    126, 55, 174, 246>>
  ```
  """
  @doc "Calculate sha224 of the binary"
  defdelegate sha224(data), to: RustyCrypt.Native
  @doc "Calculate sha256 of the binary"
  defdelegate sha256(data), to: RustyCrypt.Native
  @doc "Calculate sha384 of the binary"
  defdelegate sha384(data), to: RustyCrypt.Native
  @doc "Calculate sha512 of the binary"
  defdelegate sha512(data), to: RustyCrypt.Native
end
