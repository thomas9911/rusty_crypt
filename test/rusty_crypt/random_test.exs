defmodule RustyCrypt.RandomTest do
  use ExUnit.Case
  doctest RustyCrypt.Random

  alias RustyCrypt.Random

  defp dice_throws(amount) do
    Enum.map(1..amount, fn _ -> Random.uniform(1, 7) end)
  end

  test "uniform is uniform" do
    # expected 3.5
    # variance 35/12 = 2.9166666666666665
    # std sqrt(25/12)

    n = 10000
    values = dice_throws(n)

    mean = Enum.sum(values) / n

    var =
      values
      |> Enum.map(fn i -> (i - mean) * (i - mean) / n end)
      |> Enum.sum()

    # poor mans check
    assert mean < 3.6
    assert mean > 3.4
    assert var < 3.0
    assert var > 2.8
  end

  test "uniform between" do
    # 0..6 is inclusive range, but uniform is exclusive
    assert Random.uniform(0, 7) in 0..6
  end

  test "uniform between large" do
    large_integer = round(:math.pow(2, 130))
    low = -large_integer
    high = large_integer
    Random.uniform(low, high) in low..high
  end
end
