defmodule DiodeClient.MerkleTree do
  @moduledoc false
  alias DiodeClient.HeapMerkleTree
  @type key_type :: binary() | integer()
  @type value_type :: term()

  @type item :: {key_type(), value_type()}
  @type hash_type :: <<_::256>>

  @type proof_type :: {proof_type, proof_type} | [any()]
  @type merkle :: {atom(), map(), any()}

  # ========================================================
  # Public Functions only in the facade
  # ========================================================
  def new() do
    HeapMerkleTree.new()
  end

  def copy(merkle = {mod, _opts, _tree}) do
    copy(merkle, mod)
  end

  def copy(merkle, mod) do
    insert_items(mod.new(), to_list(merkle))
  end

  def difference(a, b) do
    a_map = MapSet.new(to_list(a))
    b_map = MapSet.new(to_list(b))
    a_diff = MapSet.difference(a_map, b_map) |> MapSet.to_list()
    b_diff = MapSet.difference(b_map, a_map) |> MapSet.to_list()

    a_diffmap =
      Enum.map(a_diff, fn {key, value} ->
        {key, {value, nil}}
      end)
      |> Map.new()

    Enum.reduce(b_diff, a_diffmap, fn {key, value}, set ->
      Map.update(set, key, {nil, value}, fn {other, nil} -> {other, value} end)
    end)
  end

  @spec insert(merkle(), key_type(), value_type()) :: merkle()
  def insert(merkle, key, value) do
    insert_items(merkle, [{key, value}])
  end

  @spec insert_item(merkle(), item()) :: merkle()
  def insert_item(merkle, item) do
    insert_items(merkle, [item])
  end

  # ========================================================
  # Wrapper functions for the impls
  # ========================================================
  @spec root_hash(merkle()) :: hash_type()
  def root_hash(merkle = {mod, _opts, _tree}) do
    mod.root_hash(merkle)
  end

  @spec root_hashes(merkle()) :: [hash_type()]
  def root_hashes(merkle = {mod, _opts, _tree}) do
    mod.root_hashes(merkle)
  end

  @spec get_proofs(merkle(), key_type()) :: proof_type()
  def get_proofs(merkle = {mod, _options, _tree}, key) do
    mod.get_proofs(merkle, key)
  end

  @spec get(merkle(), key_type()) :: value_type()
  def get(merkle = {mod, _options, _tree}, key) do
    mod.get(merkle, key)
  end

  @spec size(merkle()) :: non_neg_integer()
  def size(merkle = {mod, _options, _tree}) do
    mod.size(merkle)
  end

  @spec bucket_count(merkle()) :: pos_integer()
  def bucket_count(merkle = {mod, _options, _tree}) do
    mod.bucket_count(merkle)
  end

  @spec to_list(merkle()) :: [item()]
  def to_list(merkle = {mod, _options, _tree}) do
    mod.to_list(merkle)
  end

  @spec delete(merkle(), key_type()) :: merkle()
  def delete(merkle = {mod, _options, _tree}, key) do
    mod.delete(merkle, key)
  end

  @spec member?(merkle(), key_type()) :: boolean()
  def member?(merkle = {mod, _opts, _tree}, key) do
    mod.member?(merkle, key)
  end

  @spec insert_items(merkle(), [item()]) :: merkle()
  def insert_items(merkle = {mod, _options, _tree}, items) do
    mod.insert_items(merkle, items)
  end
end
