Benchee.run(
  %{
    "rust" => fn input -> RustyCrypt.Native.sha256(input) end,
    "elixir" => fn input -> :crypto.hash(:sha256, input) end
  },
  inputs: %{
    "Small" => List.duplicate("hallo", 2) |> :erlang.list_to_binary,
    "Medium" => List.duplicate("hallo", 20) |> :erlang.list_to_binary,
    "Bigger" => List.duplicate("hallo", 500) |> :erlang.list_to_binary
  },
  print: [fast_warning: false]
)


# ##### With input Bigger #####
# Name             ips        average  deviation         median         99th %
# rust        398.81 K        2.51 μs   ±341.25%        2.38 μs        2.93 μs
# elixir      352.55 K        2.84 μs   ±423.33%        2.79 μs        4.33 μs

# Comparison:
# rust        398.81 K
# elixir      352.55 K - 1.13x slower +0.33 μs

# ##### With input Medium #####
# Name             ips        average  deviation         median         99th %
# rust        757.17 K        1.32 μs   ±410.68%        1.40 μs        1.89 μs
# elixir      710.27 K        1.41 μs   ±688.54%        1.40 μs        1.96 μs

# Comparison:
# rust        757.17 K
# elixir      710.27 K - 1.07x slower +0.0872 μs

# ##### With input Small #####
# Name             ips        average  deviation         median         99th %
# rust        780.63 K        1.28 μs   ±552.88%        1.40 μs        1.89 μs
# elixir      734.49 K        1.36 μs   ±683.27%        1.40 μs        1.96 μs

# Comparison:
# rust        780.63 K
# elixir      734.49 K - 1.06x slower +0.0805 μs
