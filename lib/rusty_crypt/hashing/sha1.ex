defmodule RustyCrypt.Hashing.Sha1 do
  @moduledoc """
  Calculate the sha1 hash of the binary

  ```elixir
  iex> RustyCrypt.Hashing.Sha1.sha("Some data")
  <<141, 114, 69, 63, 16, 7, 154, 243, 223, 199, 252, 252, 65, 9, 177, 237, 85, 225, 131, 159>>
  ```
  """
  @doc "Calculate sha of the binary"
  defdelegate sha(data), to: RustyCrypt.Native, as: :sha1
end
