defmodule RustyCrypt do
  use Rustler, otp_app: :rusty_crypt, crate: "rusty_crypt"

  # When your NIF is loaded, it will override this function.
  def sha256(_a), do: :erlang.nif_error(:nif_not_loaded)
  def aes256gcm(_key, _text, _iv), do: :erlang.nif_error(:nif_not_loaded)
  
end

