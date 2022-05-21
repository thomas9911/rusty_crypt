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
    "Bigger" => List.duplicate("hallo", 500) |> :erlang.list_to_binary,
    "1mb" => RustyCrypt.Native.fast_random_bytes(1024**2),
    # "100mb" => RustyCrypt.Native.fast_random_bytes(100 * 1024**2)
  },
  print: [fast_warning: false]
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




# i7 with RUSTFLAGS
# ##### With input Bigger #####
# Name             ips        average  deviation         median
#    99th %
# elixir      335.77 K        2.98 μs    ±35.16%        3.07 μs
#   6.14 μs
# rust        311.86 K        3.21 μs   ±152.15%           0 μs
#  10.24 μs

# Comparison:
# elixir      335.77 K
# rust        311.86 K - 1.08x slower +0.23 μs

# ##### With input Medium #####
# Name             ips        average  deviation         median
#    99th %
# rust          1.10 M        0.91 μs    ±72.27%        1.02 μs
#   3.07 μs
# elixir        0.80 M        1.25 μs    ±48.92%        1.02 μs
#   3.07 μs

# Comparison:
# rust          1.10 M
# elixir        0.80 M - 1.37x slower +0.33 μs

# ##### With input Small #####
# Name             ips        average  deviation         median
#    99th %
# rust          1.22 M        0.82 μs    ±78.60%        1.02 μs
#   3.07 μs
# elixir        0.93 M        1.07 μs  ±1880.33%           0 μs
# 102.40 μs

# Comparison:
# rust          1.22 M
# elixir        0.93 M - 1.31x slower +0.25 μs




# i7 without flags
# ##### With input Bigger #####
# Name             ips        average  deviation         median
#    99th %
# elixir      315.25 K        3.17 μs   ±157.43%           0 μs
#  10.24 μs
# rust        210.44 K        4.75 μs   ±113.32%           0 μs
#  10.24 μs

# Comparison:
# elixir      315.25 K
# rust        210.44 K - 1.50x slower +1.58 μs

# ##### With input Medium #####
# Name             ips        average  deviation         median
#    99th %
# rust        778.18 K        1.29 μs    ±82.37%        1.02 μs
#   4.10 μs
# elixir      755.19 K        1.32 μs   ±360.43%           0 μs
#  10.24 μs

# Comparison:
# rust        778.18 K
# elixir      755.19 K - 1.03x slower +0.0391 μs

# ##### With input Small #####
# Name             ips        average  deviation         median
#    99th %
# rust          1.11 M      903.21 ns    ±21.14%      819.20 ns     1638.40 ns
# elixir        1.09 M      914.73 ns    ±60.68%        1024 ns
#   2048 ns

# Comparison:
# rust          1.11 M
# elixir        1.09 M - 1.01x slower +11.52 ns
