# AGENTS.md — DiodeClient

Context and conventions for AI agents and contributors working on this repository.

## Project context

**What it is**: DiodeClient is an Elixir library for secure P2P connections via the Diode network, using Ethereum-style addresses (e.g. `0x...`) and TLS + secp256k1 authentication.

**Key capabilities**: Port listen/connect, wallet/identity, blockchain shells (Moonbeam, Oasis Sapphire), smart-contract interaction (ABI, EIP-712, BNS, etc.).

## Coding guidelines

- **Avoid code duplication** — extract shared logic into helpers or modules.
- **Credo** (`.credo.exs`): Max nesting 3, max cyclomatic complexity 14. Predicate function names check is disabled.
- **Types**: Use `@spec` for public APIs where helpful. Dialyzer is part of the lint pipeline. Optional dependencies (e.g. Plug.Cowboy) are listed in `.dialyzer_ignore.exs` when not in deps.
- **Documentation**: Use `@moduledoc` and `@doc` for public modules and functions; `@doc false` for internal APIs (see `lib/diode_client.ex` and `lib/diode_client/abi.ex`).

## Formatting (mix format)

- **Config**: `.formatter.exs` — inputs are `mix.exs`, `.formatter.exs`, and all `*.{ex,exs}` under `config/`, `lib/`, `test/`, `scripts/`.
- **Commands**:
  - Format code: `mix format`
  - Check only (CI): `mix format --check-formatted`
- **When**: Run `mix format` before committing. CI runs `mix lint`, which includes `format --check-formatted`.

## Testing best practices

- **Framework**: ExUnit. `test/test_helper.exs` only calls `ExUnit.start()`.
- **Structure**: One test module per lib module when it makes sense (e.g. `abi_test.exs` for `ABI`, `eip712_test.exs` for `EIP712`). Use `alias DiodeClient.{...}` at the top of the test module.
- **Async**: Use `async: true` (default) for tests that do not touch shared/global state. Use `async: false` when tests start the application or use `DiodeClient.interface_add` or other global state (see `DiodeClientTest`).
- **Doctests**: Add `doctest ModuleName` in tests where the module has good `@doc` examples (e.g. `DiodeClient`, `DiodeClient.EIP712`).
- **Fixtures**: Put static files in `test/testdata/` (e.g. JSON, ABI, bin) and load with `File.read!/1` and `Jason.decode!/1` or similar; avoid hardcoding large payloads in tests.
- **Naming**: Test names should describe the scenario, e.g. `"sign and verify"`, `"encode_type"`, `"reference"`.
- **CI**: Lint runs in `.github/workflows/ci.yml` via `mix lint`; `mix test` is present but commented out. Run tests locally; CI may enable them later.

## Lint and tooling

- **Full check**: `mix lint` (alias in `mix.exs`) runs compile, `format --check-formatted`, Credo, and Dialyzer. Run this before pushing.
- **Elixir/OTP**: CI uses Elixir 1.15.8 and OTP 26. Use `.tool-versions` for local version alignment.
