Benchee.run(
  %{
    "rust" => fn input -> RustyCrypt.sha256(input) end,
    "elixir" => fn input -> :crypto.hash(:sha256, input) end
  },
  inputs: %{
    "Small" => List.duplicate("hallo", 2) |> :erlang.list_to_binary,
    "Medium" => List.duplicate("hallo", 20) |> :erlang.list_to_binary,
    "Bigger" => List.duplicate("hallo", 500) |> :erlang.list_to_binary
  }
)


# ##### With input Bigger #####
# Name             ips        average  deviation         median         99th %
# rust        399.79 K        2.50 μs   ±315.04%        2.38 μs        2.93 μs
# elixir      361.20 K        2.77 μs   ±460.87%        2.44 μs        4.26 μs

# Comparison: 
# rust        399.79 K
# elixir      361.20 K - 1.11x slower +0.27 μs

# ##### With input Medium #####
# Name             ips        average  deviation         median         99th %
# rust        759.40 K        1.32 μs   ±642.54%        1.40 μs        1.89 μs
# elixir      703.62 K        1.42 μs   ±689.34%        1.40 μs        1.96 μs

# Comparison: 
# rust        759.40 K
# elixir      703.62 K - 1.08x slower +0.104 μs

# ##### With input Small #####
# Name             ips        average  deviation         median         99th %
# rust        766.71 K        1.30 μs   ±730.55%        1.40 μs        1.89 μs
# elixir      735.48 K        1.36 μs   ±506.81%        1.40 μs        1.96 μs

# Comparison: 
# rust        766.71 K
# elixir      735.48 K - 1.04x slower +0.0554 μs
#