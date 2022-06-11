defmodule RustyCrypt.Random do
  @moduledoc """
  implemented datatypes:
  - `RustyCrypt.Random.Bytes`
  """

  @doc """
  Generate a integer between `low` and `high`

  Uses Rust's [rand::ThreadRng](https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html)
  which is a struct that uses ChaCha12 for generating random numbers and operating system’s random number source
  for seeding. Also automatically reseeds after a specific amount of bytes. Check their documentation for more details.

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
