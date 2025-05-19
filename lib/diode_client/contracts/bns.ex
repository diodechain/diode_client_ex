defmodule DiodeClient.Contracts.BNS do
  @moduledoc """
  Wrapper for BNS smart contract to register and resolve names.
  """
  import DiodeClient.Contracts.Utils
  alias DiodeClient.{Hash}
  @slot_names 1
  @slot_reverse_names 2

  defmodule Impl do
    @moduledoc false
    defstruct [:address, :shell, :postfix]
  end

  alias __MODULE__.Impl

  def impls() do
    [
      %Impl{
        address: Hash.to_address(0xAF60FAA5CD840B724742F1AF116168276112D6A6),
        shell: DiodeClient.Shell,
        postfix: "diode"
      },
      %Impl{
        address: Hash.to_address(0x75140F88B0F4B2FBC6DADC16CC51203ADB07FE36),
        shell: DiodeClient.Shell.MoonbaseAlpha,
        postfix: "m1"
      },
      %Impl{
        address: Hash.to_address(0x8A093E3A83F63A00FFFC4729AA55482845A49294),
        shell: DiodeClient.Shell.Moonbeam,
        postfix: "glmr"
      },
      %Impl{
        address: Hash.to_address(0xBC7A66A80E760DD0D84F6E39DF6CFD937C6C94F6),
        shell: DiodeClient.Shell.OasisSapphire,
        postfix: "sapphire"
      }
    ]
  end

  def all_names_length(shell, block \\ nil) do
    impl = Enum.find(impls(), fn impl -> impl.shell == shell end)

    call(impl, "AllNamesLength", [], [], block: block, result_types: "uint256")
  end

  def is_bns(address) do
    Enum.any?(impls(), fn impl -> impl.address == address end)
  end

  def register(name, destination) do
    {impl, name} = name_to_impl(name)
    cast(impl, "Register", ["string", "address"], [name, destination])
  end

  def unregister(name) do
    {impl, name} = name_to_impl(name)
    cast(impl, "Unregister", ["string"], [name])
  end

  def register_multiple(name, destinations) do
    {impl, name} = name_to_impl(name)
    cast(impl, "RegisterMultiple", ["string", "address[]"], [name, destinations])
  end

  def register_reverse(destination, name) do
    {impl, name} = name_to_impl(name)
    cast(impl, "RegisterReverse", ["address", "string"], [destination, name])
  end

  def resolve_entry(name, block) do
    {impl, name} = name_to_impl(name)

    [[destination, owner, name, lock_end, lease_end]] =
      call(impl, "ResolveEntry", ["string"], [name],
        block: block,
        result_types: ["(address,address,string,uint256,uint256)"]
      )

    %{
      destination: destination,
      owner: owner,
      name: name,
      lock_end: lock_end,
      lease_end: lease_end
    }
  end

  def resolve_name(name, block \\ nil)

  def resolve_name("", _block) do
    nil
  end

  def resolve_name(name, block) do
    {impl, name} = name_to_impl(name)

    if impl.shell == DiodeClient.Shell do
      name_hash = Hash.keccak_256(name)
      base = Hash.to_bytes32(@slot_names)
      address(impl.shell, impl.address, Hash.keccak_256(name_hash <> base), block)
    else
      resolve_entry(name, block).destination
    end
  end

  def resolve_name_owner(name, block \\ nil) do
    {_shell, addr} = resolve_name_owner_ext(name, block)
    addr
  end

  def resolve_name_owner_ext(name, block \\ nil) do
    {impl, domain} = name_to_impl(name)

    if impl.shell == DiodeClient.Shell do
      name_hash = Hash.keccak_256(domain)
      base = Hash.to_bytes32(@slot_names)

      addr =
        address(impl.shell, impl.address, Hash.keccak_256(name_hash <> base) |> add(1), block)

      {impl.shell, addr}
    else
      {impl.shell, resolve_entry(name, block).owner}
    end
  end

  def resolve_name_all(orig_name, block \\ nil) do
    {impl, name} = name_to_impl(orig_name)
    name_hash = Hash.keccak_256(name)
    base = Hash.to_bytes32(@slot_names)

    array_slot = Hash.keccak_256(name_hash <> base) |> add(3)
    size = number(impl.shell, impl.address, array_slot, block)

    if size == 0 do
      name = resolve_name(orig_name)

      if name == nil do
        []
      else
        [name]
      end
    else
      array_start = Hash.keccak_256(array_slot)

      Enum.map(1..size, fn idx ->
        address(impl.shell, impl.address, add(array_start, idx - 1), block)
      end)
    end
  end

  def resolve_address(address, block \\ nil) do
    base = Hash.to_bytes32(@slot_reverse_names)
    slot = Hash.keccak_256(Hash.to_bytes32(address) <> base)

    # either(:string, [slot, block])
    Enum.find_value(["diode", "glmr"], fn postfix ->
      impl = Enum.find(impls(), fn impl -> impl.postfix == postfix end)

      if impl.shell.get_account_root(impl.address) != nil do
        maybe_extend(string(impl.shell, impl.address, slot, block), "." <> postfix)
      end
    end)
  end

  defp maybe_extend("", _), do: nil
  defp maybe_extend(nil, _), do: nil
  defp maybe_extend(str, postfix), do: str <> postfix

  defp cast(impl, method, types, args) do
    impl.shell.send_transaction(impl.address, method, types, args, meta_transaction: true)
  end

  defp call(impl, method, types, args, opts) do
    impl.shell.call(impl.address, method, types, args, opts)
  end

  defp name_to_impl(name) do
    [name, postfix] = String.split(name, ".")
    impl = Enum.find(impls(), fn impl -> impl.postfix == postfix end)
    {impl, name}
  end

  def name_to_shell(name) do
    with [_name, postfix] <- String.split(name, "."),
         impl when not is_nil(impl) <- Enum.find(impls(), fn impl -> impl.postfix == postfix end) do
      impl.shell
    end
  end
end
