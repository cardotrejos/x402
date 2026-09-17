defmodule X402.Extensions.SIWX.ServerTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.SIWX.Server

  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Extensions.SIWX
  alias X402.Extensions.SIWX.ETSStorage
  alias X402.Extensions.SIWX.Server
  alias X402.Signer.LocalKey

  @private_key "0x" <> String.duplicate("11", 32)
  @address "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @evm_chain "eip155:8453"
  @resource "https://api.example.com/premium"
  @base [
    domain: "api.example.com",
    uri: "https://api.example.com",
    supported_chains: [%{chain_id: @evm_chain}]
  ]

  defmodule FailingCache do
    @behaviour X402.Extensions.PaymentIdentifier.Cache

    @impl true
    def get(_cache, _key), do: :miss
    @impl true
    def put(_cache, _key, _value), do: {:error, :down}
    @impl true
    def put_new(_cache, _key, _value), do: {:error, :down}
    @impl true
    def delete(_cache, _key), do: :ok
  end

  defmodule FailingStorage do
    @behaviour X402.Extensions.SIWX.Storage

    @impl true
    def get(_address, _resource), do: {:error, :not_found}
    @impl true
    def put(_address, _resource, _proof, _ttl_ms), do: {:error, :storage_full}
    @impl true
    def delete(_address, _resource), do: :ok
  end

  defmodule BareStorage do
    @behaviour X402.Extensions.SIWX.Storage

    @impl true
    def get(_address, _resource), do: {:error, :not_found}
    @impl true
    def put(_address, _resource, _proof, _ttl_ms), do: :ok
    @impl true
    def delete(_address, _resource), do: :ok
  end

  describe "new/1 and option validators" do
    test "accepts nonce cache shorthands and adapter tuples" do
      assert {:ok, %{nonce_cache: {ETSCache, :my_cache}}} =
               Server.new(@base ++ [nonce_cache: :my_cache])

      assert {:ok, %{nonce_cache: {ETSCache, pid}}} = Server.new(@base ++ [nonce_cache: self()])
      assert pid == self()

      assert {:ok, %{nonce_cache: {ETSCache, {:via, Registry, :x}}}} =
               Server.new(@base ++ [nonce_cache: {:via, Registry, :x}])

      assert {:ok, %{nonce_cache: {FailingCache, :ref}}} =
               Server.new(@base ++ [nonce_cache: {FailingCache, :ref}])

      assert {:error, %NimbleOptions.ValidationError{message: message}} =
               Server.new(@base ++ [nonce_cache: {:name, :node}])

      assert message =~ "wrap it explicitly"

      assert {:error, %NimbleOptions.ValidationError{}} = Server.new(@base ++ [nonce_cache: "x"])
    end

    test "validates storage modules and {module, server} tuples" do
      assert {:ok, %{storage: BareStorage}} = Server.new(@base ++ [storage: BareStorage])

      assert {:ok, %{storage: {ETSStorage, :store}}} =
               Server.new(@base ++ [storage: {ETSStorage, :store}])

      assert {:error, %NimbleOptions.ValidationError{message: message}} =
               Server.new(@base ++ [storage: {BareStorage, :store}])

      assert message =~ "get/3, put/5, and delete/3"

      assert {:error, %NimbleOptions.ValidationError{}} =
               Server.new(@base ++ [storage: {String, :x}])

      assert {:error, %NimbleOptions.ValidationError{}} = Server.new(@base ++ [storage: Enum])
    end

    test "new!/1 raises and validate_options/1 reports messages" do
      assert_raise NimbleOptions.ValidationError, fn -> Server.new!(domain: "x") end
      assert {:ok, %{domain: "api.example.com"}} = Server.validate_options(@base)
      assert {:error, message} = Server.validate_options(domain: "x")
      assert message =~ "required"
      assert {:error, _message} = Server.validate_options(%{})
    end
  end

  describe "challenge/1 and remember_nonce/2" do
    test "records the nonce as issued when a cache is configured" do
      cache = start_cache()
      siwx = Server.new!(@base ++ [nonce_cache: cache, statement: "Sign in"])

      assert {:ok, challenge} = Server.challenge(siwx)
      assert challenge["info"]["statement"] == "Sign in"
      nonce = challenge["info"]["nonce"]

      assert {:hit, {:siwx_nonce, :issued}} = ETSCache.get(cache, "siwx:issued:" <> nonce)
      assert :ok = Server.remember_nonce(siwx, nonce)
    end

    test "is a no-op without a cache and fails when the cache is down" do
      assert :ok = Server.remember_nonce(Server.new!(@base), "abc")

      failing = Server.new!(@base ++ [nonce_cache: {FailingCache, :ref}])
      assert Server.challenge(failing) == {:error, :down}
    end
  end

  describe "authenticate/3, record_payment/4, and revoke/3" do
    test "EVM records, lookups, proof authentication and revocation ignore address case" do
      storage = start_storage()
      siwx = Server.new!(@base ++ [storage: {ETSStorage, storage}])
      checksummed = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAfF2A"

      assert :ok = Server.record_payment(siwx, checksummed, @resource, :paid)
      assert {:ok, %{payment_proof: :paid}} = ETSStorage.get(storage, @address, @resource)
      assert {:ok, _record} = Server.authorized(siwx, @address, @resource)
      assert {:ok, _record} = Server.authorized(siwx, checksummed, @resource)
      assert {:ok, %{address: @address}} = Server.authenticate(siwx, proof(siwx), @resource)

      assert :ok = Server.revoke(siwx, checksummed, @resource)
      assert {:error, :not_authorized} = Server.authorized(siwx, @address, @resource)

      assert :ok = Server.record_payment(siwx, @address, @resource, :paid)
      assert {:ok, _record} = Server.authorized(siwx, checksummed, @resource)
      assert :ok = Server.revoke(siwx, @address, @resource)
      assert {:error, :not_authorized} = Server.authorized(siwx, checksummed, @resource)
    end

    test "Solana addresses remain case-sensitive" do
      storage = start_storage()
      siwx = Server.new!(@base ++ [storage: {ETSStorage, storage}])
      address = "9xQeWvG816bUx9EPfQmQTYnC16hHhV6bQf8kX6y4YB9"
      other = String.downcase(address)

      assert :ok = Server.record_payment(siwx, address, @resource, :paid)
      assert {:ok, _record} = Server.authorized(siwx, address, @resource)
      assert {:error, :not_authorized} = Server.authorized(siwx, other, @resource)
      assert :ok = Server.revoke(siwx, other, @resource)
      assert {:ok, _record} = Server.authorized(siwx, address, @resource)
      assert :ok = Server.revoke(siwx, address, @resource)
      assert {:error, :not_authorized} = Server.authorized(siwx, address, @resource)
    end

    test "authorizes only addresses with a payment record for the resource" do
      storage = start_storage()
      cache = start_cache()
      siwx = Server.new!(@base ++ [storage: {ETSStorage, storage}, nonce_cache: cache])

      assert Server.authenticate(siwx, proof(siwx), @resource) == {:error, :not_authorized}
      assert :ok = Server.record_payment(siwx, @address, @resource, %{"success" => true})

      assert {:ok, session} = Server.authenticate(siwx, proof(siwx), @resource)
      assert session.address == @address
      assert session.chain_id == @evm_chain
      assert session.access.payment_proof == %{"success" => true}
      assert is_integer(session.access.expires_at_ms)

      assert Server.authenticate(siwx, proof(siwx), @resource <> "/other") ==
               {:error, :not_authorized}

      assert :ok = Server.revoke(siwx, @address, @resource)
      assert Server.authenticate(siwx, proof(siwx), @resource) == {:error, :not_authorized}
    end

    test "returns verification errors and decode errors" do
      siwx = Server.new!(@base)
      other = Server.new!(Keyword.put(@base, :domain, "other.example.com"))

      assert Server.authenticate(siwx, proof(other), @resource) ==
               {:error, :invalid_siwx_domain_mismatch}

      assert Server.authenticate(siwx, "%%", @resource) == {:error, :invalid_base64}
      assert Server.verify(siwx, proof(siwx)) |> elem(0) == :ok
    end

    test "consumes nonces so a proof authenticates once" do
      storage = start_storage()
      cache = start_cache()
      siwx = Server.new!(@base ++ [storage: {ETSStorage, storage}, nonce_cache: cache])
      :ok = Server.record_payment(siwx, @address, @resource, :paid)
      header = proof(siwx)

      assert {:ok, _session} = Server.authenticate(siwx, header, @resource)
      assert Server.authenticate(siwx, header, @resource) == {:error, :invalid_siwx_nonce}
    end

    test "uses module-form storage and surfaces storage errors" do
      siwx = Server.new!(@base ++ [storage: FailingStorage])

      assert Server.record_payment(siwx, @address, @resource, :paid) == {:error, :storage_full}
      assert Server.authorized(siwx, @address, @resource) == {:error, :not_authorized}
      assert Server.revoke(siwx, @address, @resource) == :ok
    end
  end

  defp proof(siwx) do
    {:ok, challenge} = Server.challenge(siwx)
    {:ok, signer} = LocalKey.new(@private_key)
    {:ok, signed} = SIWX.sign(challenge, signer, chain_id: @evm_chain)
    {:ok, header} = SIWX.encode_signed(signed)
    header
  end

  defp start_cache do
    name = String.to_atom("siwx_server_cache_#{System.unique_integer([:positive, :monotonic])}")
    start_supervised!({ETSCache, name: name, ttl_ms: 60_000})
    name
  end

  defp start_storage do
    suffix = System.unique_integer([:positive, :monotonic])
    name = String.to_atom("siwx_server_storage_#{suffix}")
    table = String.to_atom("siwx_server_storage_table_#{suffix}")
    start_supervised!({ETSStorage, name: name, table: table})
    name
  end
end
