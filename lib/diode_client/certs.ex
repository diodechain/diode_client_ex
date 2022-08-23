defmodule DiodeClient.Certs do
  @moduledoc false
  alias DiodeClient.Secp256k1

  def extract(socket) do
    {:ok, cert} = :ssl.peercert(socket)
    id_from_der(cert)
  end

  def id_from_file(filename) do
    pem = :public_key.pem_decode(File.read!(filename))
    cert = :proplists.lookup(:Certificate, pem)
    der_cert = :erlang.element(2, cert)
    id_from_der(der_cert)
  end

  def private_from_file(filename) do
    pem = :public_key.pem_decode(File.read!(filename))
    cert = :proplists.lookup(:PrivateKeyInfo, pem)

    :public_key.der_decode(:PrivateKeyInfo, :erlang.element(2, cert))
    |> getfield(:ECPrivateKey, :privateKey)
  end

  def id_from_der(der_encoded_cert) when is_binary(der_encoded_cert) do
    :public_key.pkix_decode_cert(der_encoded_cert, :otp)
    |> id_from_der()
  end

  def id_from_der(cert) do
    getfield(cert, :OTPCertificate, :tbsCertificate)
    |> getfield(:OTPTBSCertificate, :subjectPublicKeyInfo)
    |> getfield(:OTPSubjectPublicKeyInfo, :subjectPublicKey)
    |> getfield(:ECPoint, :point)
    |> Secp256k1.compress_public()
  end

  @spec getfield(any(), atom(), atom()) :: any()
  def getfield(record, type, fieldname) do
    record_def = extract_record(type)
    Keyword.get(keywords(record_def, record), fieldname)
  end

  @types [:ECPrivateKey, :OTPCertificate, :OTPTBSCertificate, :OTPSubjectPublicKeyInfo, :ECPoint]
  for type <- @types do
    record = Record.extract(type, from_lib: "public_key/include/public_key.hrl")

    Module.eval_quoted(
      __MODULE__,
      Code.string_to_quoted("""
        def extract_record(:#{Atom.to_string(type)}) do
          #{inspect(record)}
        end
      """)
    )
  end

  @spec keywords([any()], any()) :: keyword()
  def keywords(record_def, record) do
    zip = List.zip([record_def, :lists.seq(1, length(record_def))])

    Keyword.new(zip, fn {{key, _default}, idx} ->
      {key, elem(record, idx)}
    end)
  end
end
