defmodule RustyCrypt do
  @moduledoc """
  Cryptographic functions inplemented via a Rust NIF.

  Modules:
  - `RustyCrypt.Cipher`
  - `RustyCrypt.Hashing`
  - `RustyCrypt.Mac`
  - `RustyCrypt.Random`

  If you want an interface more like the erlang `:crypto` module go to `RustyCrypt.Erlang`

  For more info on the Rust implementation details check the `./native` folder
  and [RustCrypto](https://github.com/RustCrypto)
  (which I used to implement the different algorithms)
  """

  @doc """
  Xors's two binarys together.

  ```elixir
  iex> RustyCrypt.xor(<<0, 0, 2, 1>>, <<0, 0, 2, 1>>)
  <<0, 0, 0, 0>>
  iex> RustyCrypt.xor(<<4, 6, 4, 4>>, <<2, 2, 2, 0>>)
  <<6, 4, 6, 4>>
  ```

  Example with xors, check if strings are the same:

  ```elixir
  iex> alias RustyCrypt.Hashing.Sha2
  ...> a = Sha2.sha256("just some text")
  ...> b = Sha2.sha256("just some text")
  ...> a |> RustyCrypt.xor(b)
  <<0 :: 256>> # 256 zero bits, so the hashes are the same
  ...> a = Sha2.sha256("just some text")
  ...> b = Sha2.sha256("other text")
  ...> a |> RustyCrypt.xor(b) |> String.slice(0..3)
  <<78, 64, 46, 149>> # not zeroes so hashes are not the same
  ```
  """
  defdelegate xor(bin1, bin2), to: RustyCrypt.Native, as: :exor

  @doc """
  Convert binary to an integer.

  ```elixir
  iex> RustyCrypt.bytes_to_integer("testing")
  32762643847147111
  iex> alias RustyCrypt.Hashing.Sha2
  ...> "just some text"
  ...> |> Sha2.sha256()
  ...> |> RustyCrypt.bytes_to_integer()
  ...> |> rem(100)
  86
  ```
  """
  defdelegate bytes_to_integer(binary), to: RustyCrypt.Native

  @doc """
  Convert iolist to binary, just like `:erlang.iolist_to_binary/1`

  ```elixir
  iex> :erlang.iolist_to_binary(["test", "test"])
  "testtest"
  iex> RustyCrypt.iolist_to_binary(["test", "test"])
  "testtest"
  ```
  """
  defdelegate iolist_to_binary(binary), to: RustyCrypt.Native
end
