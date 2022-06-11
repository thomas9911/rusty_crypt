defmodule RustyCrypt.Random do
  @moduledoc """
  implemented datatypes:
  - `RustyCrypt.Random.Bytes`
  """

  defdelegate uniform(low, high), to: RustyCrypt.Native, as: :rand_uniform
end
