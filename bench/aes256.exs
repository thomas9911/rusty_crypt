iv = <<1::96>>
key = <<0::256>>
aad = <<>>

Benchee.run(
  %{
    "rust" => fn input -> RustyCrypt.Native.aes256gcm_encrypt(key, iv, input, aad) end,
    "elixir" => fn input -> :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, input, aad, true) end
  },
  inputs: %{
    "Small" => List.duplicate("hallo", 2) |> :erlang.list_to_binary,
    "Medium" => List.duplicate("hallo", 20) |> :erlang.list_to_binary,
    "Bigger" => List.duplicate("hallo", 500) |> :erlang.list_to_binary
  }
)


# ##### With input Bigger #####
# Name             ips        average  deviation         median         99th %
# elixir      353.12 K        2.83 μs   ±564.61%        2.38 μs        5.87 μs
# rust        261.45 K        3.82 μs   ±474.17%        3.77 μs        6.15 μs

# Comparison:
# elixir      353.12 K
# rust        261.45 K - 1.35x slower +0.99 μs

# ##### With input Medium #####
# Name             ips        average  deviation         median         99th %
# elixir      490.77 K        2.04 μs  ±1495.90%        1.89 μs        2.86 μs
# rust        477.57 K        2.09 μs  ±1027.91%        1.89 μs        2.86 μs

# Comparison:
# elixir      490.77 K
# rust        477.57 K - 1.03x slower +0.0563 μs

# ##### With input Small #####
# Name             ips        average  deviation         median         99th %
# elixir      569.68 K        1.76 μs  ±1005.72%        1.82 μs        2.38 μs
# rust        527.11 K        1.90 μs  ±1005.01%        1.89 μs        2.44 μs

# Comparison:
# elixir      569.68 K
# rust        527.11 K - 1.08x slower +0.142 μs


# # with `RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"`
# ##### With input Bigger #####
# Name             ips        average  deviation         median         99th %
# rust        324.44 K        3.08 μs   ±665.79%        2.86 μs        5.17 μs
# elixir      321.09 K        3.11 μs   ±598.35%        2.44 μs        9.92 μs

# Comparison:
# rust        324.44 K
# elixir      321.09 K - 1.01x slower +0.0322 μs

# ##### With input Medium #####
# Name             ips        average  deviation         median         99th %
# rust        557.46 K        1.79 μs   ±907.40%        1.47 μs        2.44 μs
# elixir      484.68 K        2.06 μs  ±1287.27%        1.89 μs        2.86 μs

# Comparison:
# rust        557.46 K
# elixir      484.68 K - 1.15x slower +0.27 μs

# ##### With input Small #####
# Name             ips        average  deviation         median         99th %
# rust        595.07 K        1.68 μs  ±1026.05%        1.47 μs        2.44 μs
# elixir      570.32 K        1.75 μs  ±1320.69%        1.82 μs        2.38 μs

# Comparison:
# rust        595.07 K
# elixir      570.32 K - 1.04x slower +0.0729 μs
