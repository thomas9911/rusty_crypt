
RustyCrypt.Native.fast_random_bytes(12) |> IO.inspect()
RustyCrypt.Native.secure_random_bytes(12) |> IO.inspect()


Benchee.run(
  %{
    "fast" => fn input -> RustyCrypt.Native.fast_random_bytes(input) end,
    "secure" => fn input -> RustyCrypt.Native.secure_random_bytes(input) end,
    "secure erlang" => fn input -> :crypto.strong_rand_bytes(input) end
  },
  inputs: %{
    "Small" => 50,
    "Medium" => 8000,
    "Bigger" => 1200000
  },
  print: [fast_warning: false]
)


# ##### With input Bigger #####
# Name             ips        average  deviation         median         99th %
# fast          2.33 K      428.57 μs    ±27.00%      409.60 μs      819.20 μs
# secure        1.33 K      750.80 μs    ±17.86%      716.80 μs     1228.80 μs

# Comparison:
# fast          2.33 K
# secure        1.33 K - 1.75x slower +322.23 μs

# ##### With input Medium #####
# Name             ips        average  deviation         median         99th %
# fast        508.75 K        1.97 μs  ±1225.87%           0 μs      102.40 μs
# secure      258.35 K        3.87 μs   ±601.78%           0 μs      102.40 μs

# Comparison:
# fast        508.75 K
# secure      258.35 K - 1.97x slower +1.91 μs

# ##### With input Small #####
# Name             ips        average  deviation         median         99th %
# secure        4.31 M      232.05 ns   ±196.93%           0 ns        1024 ns
# fast          3.00 M      333.85 ns    ±22.72%      307.20 ns      614.40 ns

# Comparison:
# secure        4.31 M
# fast          3.00 M - 1.44x slower +101.81 ns


# ##### With input Bigger #####
# Name                    ips        average  deviation         median         99th %
# fast                 2.56 K      390.71 μs    ±24.70%      409.60 μs      614.40 μs
# secure               1.52 K      657.88 μs    ±13.71%      614.40 μs      921.60 μs
# secure erlang        0.30 K     3279.83 μs     ±7.38%     3174.40 μs     4198.40 μs

# Comparison:
# fast                 2.56 K
# secure               1.52 K - 1.68x slower +267.17 μs
# secure erlang        0.30 K - 8.39x slower +2889.12 μs

# ##### With input Medium #####
# Name                    ips        average  deviation         median         99th %
# fast               655.87 K        1.52 μs   ±265.99%           0 μs       10.24 μs
# secure             301.73 K        3.31 μs   ±145.96%           0 μs       10.24 μs
# secure erlang       45.49 K       21.98 μs    ±18.51%       20.48 μs       30.72 μs

# Comparison:
# fast               655.87 K
# secure             301.73 K - 2.17x slower +1.79 μs
# secure erlang       45.49 K - 14.42x slower +20.46 μs

# ##### With input Small #####
# Name                    ips        average  deviation         median         99th %
# secure               4.85 M      206.08 ns    ±21.81%      204.80 ns      409.60 ns
# fast                 2.34 M      427.15 ns  ±2709.85%           0 ns           0 ns
# secure erlang        0.54 M     1844.04 ns   ±781.31%           0 ns      102400 ns

# Comparison:
# secure               4.85 M
# fast                 2.34 M - 2.07x slower +221.06 ns
# secure erlang        0.54 M - 8.95x slower +1637.95 ns
