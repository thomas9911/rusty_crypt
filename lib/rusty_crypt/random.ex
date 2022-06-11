defmodule RustyCrypt.Random do
  @moduledoc """
  implemented datatypes:
  - `RustyCrypt.Random.Bytes`
  """

  @doc """
  Generate a integer between `low` and `high`

  ```elixir
  iex> RustyCrypt.Random.uniform(-10, 10) in -10..9
  true
  iex> large_integer = round(:math.pow(2, 64))
  ...> low = -large_integer
  ...> high = large_integer
  ...> RustyCrypt.Random.uniform(low, high) in low..high
  true
  ```
  """
  @spec uniform(integer, integer) :: binary
  defdelegate uniform(low, high), to: RustyCrypt.Native, as: :rand_uniform
end
