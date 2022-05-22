RustyCrypt.Native.iolist_to_binary(<<>>) |> IO.inspect()
:erlang.iolist_to_binary(<<>>) |> IO.inspect()

Benchee.run(
  %{
    "rust" => fn input -> RustyCrypt.Native.iolist_to_binary(input) end,
    "erlang" => fn input -> :erlang.iolist_to_binary(input) end,
  },
  inputs: %{
    "Small" => <<>>,
    "Medium" => RustyCrypt.Native.secure_random_bytes(12000),
    "Bigger" => RustyCrypt.Native.secure_random_bytes(1200000),
    "even Bigger" => RustyCrypt.Native.secure_random_bytes(12000000)
    },
  # inputs: %{
  #   "Small" => [],
  #   "Medium" => RustyCrypt.Native.secure_random_bytes(12000) |> :erlang.binary_to_list(),
  #   "Bigger" => RustyCrypt.Native.secure_random_bytes(1200000) |> :erlang.binary_to_list(),
  #   "even Bigger" => RustyCrypt.Native.secure_random_bytes(12000000) |> :erlang.binary_to_list()
  # },
  print: [fast_warning: false]
)

# binaries are O(1) on elixir and rust (however elixir is faster)
# lists are very slow (both elixir and rust)
