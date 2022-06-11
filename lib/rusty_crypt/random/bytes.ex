defmodule RustyCrypt.Random.Bytes do
  @moduledoc """
  Generate random bytes.

  Has two methods: `secure_random/1` and `fast_random/1`

  Note that based on the name you could think that one is super fast and the other one is super slow,
  while actually they are quite comparible in speed.
  So if you don't know which one to use just use `secure_random/1`.

  Test the speed yourself after cloning the repo with the command:
  ```sh
  mix bench.random
  ```
  """

  @doc """
  This function is similar to `:crypto.strong_rand_bytes/1`

  Uses Rust's [rand::ThreadRng](https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html)
  which is a struct that uses ChaCha12 for generating random numbers and operating system’s random number source
  for seeding. Also automatically reseeds after a specific amount of bytes. Check their documentation for more details.

  ```elixir
  iex> RustyCrypt.Random.Bytes.secure_random(12) |> byte_size()
  12
  ```
  """
  @spec secure_random(pos_integer) :: binary
  defdelegate secure_random(amount), to: RustyCrypt.Native, as: :secure_random_bytes

  @doc """
  This function is similar to `:rand.bytes/1`

  uses Rust's [rand::SmallRng](https://docs.rs/rand/latest/rand/rngs/struct.SmallRng.html)
  which is a struct that uses Xoshiro256PlusPlus for generating random numbers which
  are not no cryptographically secure. Check their documentation for more details.

  ```elixir
  iex> RustyCrypt.Random.Bytes.fast_random(12) |> byte_size()
  12
  ```
  """
  @spec fast_random(pos_integer) :: binary
  defdelegate fast_random(amount), to: RustyCrypt.Native, as: :fast_random_bytes
end
