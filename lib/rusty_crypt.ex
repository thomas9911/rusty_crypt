defmodule RustyCrypt do
  @moduledoc """
  Cryptographic functions inplemented via a Rust nif.

  If you want an interface more like the erlang `:crypto` module go to `RustyCrypt.Erlang`
  """
  use Rustler, otp_app: :rusty_crypt, crate: "rusty_crypt"

  @spec sha224(binary) :: binary
  def sha224(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha256(binary) :: binary
  def sha256(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha384(binary) :: binary
  def sha384(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha512(binary) :: binary
  def sha512(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec aes256gcm_encrypt(key :: binary, data :: binary, iv :: binary, aad :: binary) ::
          {:ok, {data :: binary, tag :: binary}} | {:error, atom}
  def aes256gcm_encrypt(_key, _data, _iv, _aad), do: :erlang.nif_error(:nif_not_loaded)

  @spec aes256gcm_decrypt(
          key :: binary,
          data :: binary,
          iv :: binary,
          aad :: binary,
          tag :: binary
        ) :: {:ok, data :: binary} | {:error, atom}
  def aes256gcm_decrypt(_key, _text, _iv, _aad, _tag), do: :erlang.nif_error(:nif_not_loaded)

  @spec chacha20_poly1305_encrypt(key :: binary, data :: binary, iv :: binary, aad :: binary) ::
          {:ok, {data :: binary, tag :: binary}} | {:error, atom}
  def chacha20_poly1305_encrypt(_key, _data, _iv, _aad), do: :erlang.nif_error(:nif_not_loaded)

  @spec chacha20_poly1305_decrypt(
          key :: binary,
          data :: binary,
          iv :: binary,
          aad :: binary,
          tag :: binary
        ) :: {:ok, data :: binary} | {:error, atom}
  def chacha20_poly1305_decrypt(_key, _text, _iv, _aad, _tag),
    do: :erlang.nif_error(:nif_not_loaded)
end
