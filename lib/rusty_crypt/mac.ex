defmodule RustyCrypt.Mac do
  @moduledoc """
  Calculate Message Authenication Codes (MAC)

  implemented MACs:
  - `RustyCrypt.Mac.Hmac`
  """

  @doc """
  Calculate mac with poly1305
  ```elixir
  iex> alias RustyCrypt.Random.Bytes
  ...> secret = Bytes.secure_random(32)
  ...> mac = RustyCrypt.Mac.poly1305(secret, "my data")
  ...> byte_size(mac)
  16
  ```
  """
  @spec poly1305(binary, binary) :: binary | {:error, :bad_key_length}
  defdelegate poly1305(secret, data), to: RustyCrypt.Native
end
