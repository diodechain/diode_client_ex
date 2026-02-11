defmodule DiodeClient.Anvil.Helper do
  @moduledoc """
  Helper to download and deploy diode_contract (https://github.com/diodechain/diode_contract)
  on a local Anvil chain for testing.

  Requires Foundry (`forge`) on PATH for contract deployment. Set ANVIL_CONTRACT_REPO_PATH
  to use an existing clone; otherwise the repo is cloned to a temporary directory.

  ## One-shot test env (for downstream test_helper.exs)

      # In your app's test/test_helper.exs:
      case DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil", deploy_contracts: false) do
        :ok ->
          :ok
        {:error, :anvil_not_reachable} ->
          ExUnit.configure(exclude: [anvil: true])
        {:error, _reason} ->
          ExUnit.configure(exclude: [anvil: true])
      end
      ExUnit.start()

  ## Example (manual steps)

      # With Anvil running (e.g. anvil) and diode_contract deployed:
      {:ok, list} = DiodeClient.Anvil.Helper.deploy_contracts()
      DiodeClient.Contracts.Factory.set_anvil_contracts(list)
  """
  alias DiodeClient.{ABI, Base16, Hash}
  alias DiodeClient.Contracts.{Factory, List}
  alias DiodeClient.Shell.Anvil

  require Logger
  @repo_url "https://github.com/diodechain/diode_contract"

  @doc """
  Returns whether the Anvil RPC endpoint is reachable (e.g. `anvil` is running).

  Use in test_helper.exs to exclude `:anvil` tests when Anvil is not running:

      if not DiodeClient.Anvil.Helper.anvil_reachable?() do
        ExUnit.configure(exclude: [anvil: true])
      end

  Optional `rpc_url` defaults to `ANVIL_RPC_URL` or `http://127.0.0.1:8545`.
  """
  def anvil_reachable?(rpc_url \\ nil) do
    url = rpc_url || Anvil.rpc_url()
    body = Jason.encode!(%{jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1})

    case post(url, body, 3_000) do
      {:ok, resp_body} ->
        case Jason.decode(resp_body) do
          {:ok, %{"result" => _}} -> true
          _ -> false
        end

      {:error, _} ->
        false
    end
  end

  @doc """
  One-shot setup for using the Anvil shell in tests.

  Call from your library's `test/test_helper.exs` before `ExUnit.start()`.
  Optionally sets a wallet, checks Anvil reachability, and deploys diode_contract
  so `DiodeClient.Contracts.Factory.contracts(DiodeClient.Shell.Anvil)` works.

  ## Options

    * `:wallet` – Path or callback for `DiodeClient.set_wallet/1`. If set, ensures
      a wallet is set (e.g. `"test_anvil"` creates/uses that file). Skip if your
      tests do not send transactions. Default: no change.
    * `:deploy_contracts` – If `true`, ensures diode_contract repo is available,
      runs `forge build`, deploys contracts to Anvil, and calls
      `Factory.set_anvil_contracts/1`. Requires Anvil reachable and Foundry on PATH.
      Default: `false`.
    * `:rpc_url` – Anvil RPC URL. Default: `ANVIL_RPC_URL` or `http://127.0.0.1:8545`.

  ## Returns

    * `:ok` – Wallet (if requested) and optional deployment succeeded.
    * `{:error, :anvil_not_reachable}` – RPC endpoint not reachable; exclude `:anvil`
      tests or start Anvil.
    * `{:error, reason}` – Deployment or wallet error (e.g. `{:clone_failed, _}`).

  ## Example (minimal: Anvil only, no contracts)

      DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
      ExUnit.start()

  ## Example (Anvil + contracts, skip anvil tests when unreachable)

      case DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil", deploy_contracts: true) do
        :ok -> :ok
        {:error, :anvil_not_reachable} -> ExUnit.configure(exclude: [anvil: true])
        {:error, _} -> ExUnit.configure(exclude: [anvil: true])
      end
      ExUnit.start()
  """
  def ensure_test_env(opts \\ []) do
    rpc_url = Keyword.get(opts, :rpc_url) || Anvil.rpc_url()
    deploy_contracts = Keyword.get(opts, :deploy_contracts, false)
    wallet_opt = Keyword.get(opts, :wallet)

    if wallet_opt != nil do
      case DiodeClient.set_wallet(wallet_opt) do
        {:error, _} -> :ok
        _ -> :ok
      end

      Anvil.set_balance(DiodeClient.address(), DiodeClient.Shell.ether(1))
    end

    if deploy_contracts do
      if anvil_reachable?(rpc_url) do
        case deploy_contracts(rpc_url, opts) do
          {:ok, _} -> :ok
          err -> err
        end
      else
        {:error, :anvil_not_reachable}
      end
    else
      :ok
    end
  end

  @anvil_port_key {__MODULE__, :anvil_port}

  @doc """
  Spawns Anvil in the background and waits until the RPC endpoint is reachable.

  Use in test_helper.exs so `mix test` works without manually starting Anvil:

      case DiodeClient.Anvil.Helper.start_anvil() do
        {:ok, _port} -> :ok
        {:error, _} -> ExUnit.configure(exclude: [anvil: true])
      end
      DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
      ExUnit.start()

  The process is kept alive for the test run (port stored in process); when the
  test runner exits, Anvil is terminated.

  ## Options

    * `:rpc_url` – URL to poll (default: `ANVIL_RPC_URL` or `http://127.0.0.1:8545`).
    * `:timeout` – Max ms to wait for Anvil to become reachable (default: `15_000`).
    * `:port` – Port for Anvil (default: parsed from `:rpc_url` or `8545`).
    * `:args` – Extra args for `anvil` (default: `[]`).

  ## Returns

    * `{:ok, port}` – Anvil is running and reachable.
    * `{:error, :executable_not_found}` – `anvil` not on PATH (install Foundry).
    * `{:error, :timeout}` – Anvil did not become reachable within `:timeout`.
    * `{:error, {:spawn_failed, reason}}` – Failed to start the process.
  """
  def start_anvil(opts \\ []) do
    rpc_url = Keyword.get(opts, :rpc_url) || Anvil.rpc_url()
    timeout_ms = Keyword.get(opts, :timeout, 15_000)
    port = Keyword.get(opts, :port) || port_from_rpc_url(rpc_url)
    extra_args = Keyword.get(opts, :args, [])

    case System.find_executable("anvil") do
      nil ->
        {:error, :executable_not_found}

      path ->
        args = ["--port", to_string(port)] ++ extra_args
        port_opts = [:binary, :exit_status, :stderr_to_stdout, {:args, args}]
        port = Port.open({:spawn_executable, path}, port_opts)
        :persistent_term.put(@anvil_port_key, port)

        deadline = System.monotonic_time(:millisecond) + timeout_ms

        if wait_reachable(rpc_url, deadline) do
          {:ok, port}
        else
          if Port.info(port) != nil, do: Port.close(port)
          :persistent_term.erase(@anvil_port_key)
          {:error, :timeout}
        end
    end
  end

  defp port_from_rpc_url("http://127.0.0.1:" <> rest) do
    rest |> String.split("/") |> hd() |> String.to_integer()
  end

  defp port_from_rpc_url("http://localhost:" <> rest) do
    rest |> String.split("/") |> hd() |> String.to_integer()
  end

  defp port_from_rpc_url(_), do: 8545

  defp wait_reachable(rpc_url, deadline) do
    if anvil_reachable?(rpc_url) do
      true
    else
      if System.monotonic_time(:millisecond) >= deadline do
        false
      else
        Process.sleep(200)
        wait_reachable(rpc_url, deadline)
      end
    end
  end

  @doc """
  Returns the path to the diode_contract repo. Uses ANVIL_CONTRACT_REPO_PATH if set;
  otherwise returns nil (caller must clone or set path).
  """
  def repo_path do
    case System.get_env("ANVIL_CONTRACT_REPO_PATH") do
      nil -> nil
      "" -> nil
      path -> path
    end
  end

  @doc """
  Ensures the diode_contract repo is available: returns path from ANVIL_CONTRACT_REPO_PATH
  or clones to a temporary directory. Returns `{:ok, path}` or `{:error, reason}`.
  """
  def ensure_repo do
    case repo_path() do
      nil ->
        dir = Path.join(Mix.Project.build_path(), "lib/diode_client/diode_contract")

        case clone_repo(dir) do
          :ok -> {:ok, dir}
          err -> err
        end

      path ->
        if File.exists?(path) do
          {:ok, path}
        else
          {:error, {:path_not_found, path}}
        end
    end
  end

  defp clone_repo(dir) do
    if File.exists?(dir) do
      :ok
    else
      File.mkdir_p!(Path.dirname(dir))

      {output, status} =
        System.cmd("git", ["clone", "--depth", "1", @repo_url, dir], stderr_to_stdout: true)

      case status do
        0 -> :ok
        _ -> {:error, {:clone_failed, output}}
      end
    end
  end

  @doc """
  Runs `forge build` in the given repo path. Returns `:ok` or `{:error, reason}`.
  """
  def build_repo(path) do
    Logger.info("Building diode_contract in #{path}")
    {output, status} = System.cmd("forge", ["build"], cd: path, stderr_to_stdout: true)

    case status do
      0 -> :ok
      _ -> {:error, {:forge_build_failed, output}}
    end
  end

  @doc """
  Deploys contracts from diode_contract to the Anvil RPC URL (default from ANVIL_RPC_URL).

  Option A: If a deploy script exists (e.g. `script/DeployAnvil.s.sol`), run it and parse
  broadcast output. Option B: Read `out/` artifacts and send deployment transactions.

  Returns `{:ok, %List{}}` and calls `Factory.set_anvil_contracts(list)` so
  `Factory.contracts(DiodeClient.Shell.Anvil)` works. Returns `{:error, reason}` on failure.
  """
  def deploy_contracts(rpc_url \\ nil, opts \\ []) do
    rpc_url = rpc_url || Anvil.rpc_url()

    with {:ok, path} <- ensure_repo(),
         :ok <- build_repo(path),
         {:ok, list} <- deploy_from_artifacts(path, rpc_url, opts) do
      Factory.set_anvil_contracts(list)
      {:ok, list}
    end
  end

  defp deploy_from_artifacts(path, rpc_url, _opts) do
    out_dir = Path.join(path, "out")
    unless File.exists?(out_dir), do: raise("out/ not found; run forge build in #{path}")

    # Contract names in deployment order; diode_contract may use different names.
    # Try common artifact paths: Contract.sol/Contract.json
    contract_names = [
      "BNS",
      "DriveFactory",
      "Drive",
      "DriveMember",
      "DriveInvites",
      "DiodeToken",
      "DiodeRegistryLight",
      "FleetContractUpgradeable"
    ]

    addresses = deploy_contracts_in_order(out_dir, contract_names, rpc_url)

    if map_size(addresses) == 0 do
      {:error, :no_contracts_deployed}
    else
      build_list(addresses)
    end
  end

  defp deploy_contracts_in_order(out_dir, contract_names, rpc_url) do
    Enum.reduce(contract_names, %{}, fn name, acc ->
      case find_and_deploy_contract(out_dir, name, rpc_url, acc) do
        {:ok, addr} -> Map.put(acc, name, addr)
        _ -> acc
      end
    end)
  end

  defp find_and_deploy_contract(out_dir, name, rpc_url, acc) do
    # Foundry layout: out/ContractName.sol/ContractName.json
    pattern = Path.join(out_dir, "**/#{name}.json")
    paths = Path.wildcard(pattern)

    case paths do
      [json_path | _] ->
        deploy_artifact(name, json_path, rpc_url, acc)

      [] ->
        {:error, {:artifact_not_found, name}}
    end
  end

  defp deploy_artifact(name, json_path, rpc_url, acc) do
    json = File.read!(json_path) |> Jason.decode!()
    bytecode_hex = get_in(json, ["bytecode", "object"]) || get_in(json, ["bytecode"])
    unless bytecode_hex, do: raise("no bytecode in #{json_path}")

    bytecode = Base16.decode(bytecode_hex)

    bytecode =
      case name do
        "Drive" ->
          bns = acc["BNS"] || raise("BNS not deployed")
          bytecode <> ABI.encode_args(["address"], [bns])

        "DriveInvites" ->
          factory = acc["DriveFactory"] || raise("DriveFactory not deployed")
          bytecode <> ABI.encode_args(["address"], [factory])

        "DiodeToken" ->
          foundation = ""
          bridge = ""
          transferable = true

          bytecode <>
            ABI.encode_args(["address", "address", "bool"], [foundation, bridge, transferable])

        "DiodeRegistryLight" ->
          foundation = ""
          token = acc["DiodeToken"] || raise("DiodeToken not deployed")
          bytecode <> ABI.encode_args(["address", "address"], [foundation, token])

        "FleetContractUpgradeable" ->
          registry = acc["DiodeRegistryLight"] || raise("DiodeRegistryLight not deployed")
          bytecode <> ABI.encode_args(["address"], [registry])

        _ ->
          bytecode
      end

    # First Anvil account
    from = Base16.decode("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

    case send_creation_tx(rpc_url, from, bytecode) do
      {:ok, contract_address} -> {:ok, contract_address}
      err -> err
    end
  end

  defp send_creation_tx(rpc_url, from, data) do
    body = %{
      jsonrpc: "2.0",
      method: "eth_sendTransaction",
      params: [
        %{
          "from" => Base16.encode(from, short: false),
          "gas" => "0x989680",
          "data" => Base16.encode(data, short: false)
        }
      ],
      id: 1
    }

    body_str = Jason.encode!(body)

    case post(rpc_url, body_str, 60_000) do
      {:ok, resp_body} ->
        case Jason.decode!(resp_body) do
          %{"result" => tx_hash} -> wait_for_receipt(rpc_url, tx_hash)
          %{"error" => err} -> {:error, err}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp wait_for_receipt(rpc_url, tx_hash, retries \\ 20) do
    body = %{jsonrpc: "2.0", method: "eth_getTransactionReceipt", params: [tx_hash], id: 1}
    body_str = Jason.encode!(body)

    case post(rpc_url, body_str, 5_000) do
      {:ok, resp_body} ->
        case Jason.decode!(resp_body) do
          %{"result" => nil} when retries > 0 ->
            Process.sleep(200)
            wait_for_receipt(rpc_url, tx_hash, retries - 1)

          %{"result" => %{"contractAddress" => addr}} when is_binary(addr) ->
            {:ok, Hash.to_address(Base16.decode(addr))}

          %{"result" => _} ->
            {:error, :no_contract_address}
        end

      _ ->
        {:error, :request_failed}
    end
  end

  defp build_list(addresses) do
    factory = addresses["DriveFactory"]

    list = %List{
      bns: Map.get(addresses, "BNS") || factory,
      bns_postfix: "anvil",
      drive_invites: Map.get(addresses, "DriveInvites") || factory,
      drive_member_version: 114,
      drive_member: Map.get(addresses, "DriveMember") || factory,
      drive_version: 159,
      drive: Map.get(addresses, "Drive") || factory,
      factory: factory,
      fleet_member: Map.get(addresses, "FleetMember") || Hash.to_address(0),
      proxy_code_hash:
        Hash.keccak_256(
          Factory.proxy_code(Anvil, factory) <>
            ABI.encode_args(["address", "address"], [0, factory])
        )
    }

    {:ok, list}
  end

  def post(url, body, timeout) do
    headers = [{~c"Content-Type", ~c"application/json"}]

    case :httpc.request(
           :post,
           {String.to_charlist(url), headers, ~c"application/json", body},
           [timeout: timeout],
           []
         ) do
      {:ok, {{_, 200, _}, _, resp_body}} when is_binary(resp_body) ->
        {:ok, resp_body}

      {:ok, {{_, 200, _}, _, resp_body}} when is_list(resp_body) ->
        {:ok, :erlang.list_to_binary(resp_body)}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
