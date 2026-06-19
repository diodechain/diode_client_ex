defmodule DiodeClient.Contracts.RegistryTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Contracts.Registry

  describe "normalize_exists/1" do
    test "returns true for ABI bool decoded as uint8 1" do
      assert Registry.normalize_exists(1)
    end

    test "returns true for boolean true" do
      assert Registry.normalize_exists(true)
    end

    test "returns false for ABI bool decoded as uint8 0" do
      refute Registry.normalize_exists(0)
    end

    test "returns false for boolean false" do
      refute Registry.normalize_exists(false)
    end
  end
end
