defmodule RustyCrypt.Native do
  @moduledoc false
  use Rustler, otp_app: :rusty_crypt, crate: "rusty_crypt"

  # module to link to the rust library, this module is there so we can define the public api how we want

  @spec sha224(binary) :: binary
  def sha224(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha256(binary) :: binary
  def sha256(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha384(binary) :: binary
  def sha384(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha512(binary) :: binary
  def sha512(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha3_224(binary) :: binary
  def sha3_224(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha3_256(binary) :: binary
  def sha3_256(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha3_384(binary) :: binary
  def sha3_384(_data), do: :erlang.nif_error(:nif_not_loaded)

  @spec sha3_512(binary) :: binary
  def sha3_512(_data), do: :erlang.nif_error(:nif_not_loaded)

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

  @spec aes256ccm_encrypt(key :: binary, data :: binary, iv :: binary, aad :: binary) ::
          {:ok, {data :: binary, tag :: binary}} | {:error, atom}
  def aes256ccm_encrypt(_key, _data, _iv, _aad), do: :erlang.nif_error(:nif_not_loaded)

  @spec aes256ccm_decrypt(
          key :: binary,
          data :: binary,
          iv :: binary,
          aad :: binary,
          tag :: binary
        ) :: {:ok, data :: binary} | {:error, atom}
  def aes256ccm_decrypt(_key, _text, _iv, _aad, _tag), do: :erlang.nif_error(:nif_not_loaded)

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

  @spec secure_random_bytes(pos_integer) :: binary
  def secure_random_bytes(_byte_size), do: :erlang.nif_error(:nif_not_loaded)
  @spec fast_random_bytes(pos_integer) :: binary
  def fast_random_bytes(_byte_size), do: :erlang.nif_error(:nif_not_loaded)

  @spec bytes_to_integer(binary) :: integer
  def bytes_to_integer(_bytes), do: :erlang.nif_error(:nif_not_loaded)
end
