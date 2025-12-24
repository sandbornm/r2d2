"""Unit tests for resource tree module."""

import pytest

from r2d2.analysis.resource_tree import (
    Resource,
    BinaryResource,
    FunctionResource,
    InstructionResource,
)


class TestResource:
    """Tests for base Resource class."""

    def test_create_resource_with_required_fields(self):
        """Test creating a resource with minimal required fields."""
        resource = Resource(kind="test", name="test_resource")

        assert resource.kind == "test"
        assert resource.name == "test_resource"
        assert resource.metadata == {}
        assert resource.children == []
        assert resource.resource_id is not None

    def test_resource_id_is_unique(self):
        """Test each resource gets a unique ID."""
        r1 = Resource(kind="test", name="r1")
        r2 = Resource(kind="test", name="r2")

        assert r1.resource_id != r2.resource_id

    def test_add_child(self):
        """Test adding child resources."""
        parent = Resource(kind="parent", name="parent")
        child = Resource(kind="child", name="child")

        parent.add_child(child)

        assert len(parent.children) == 1
        assert parent.children[0] is child

    def test_add_multiple_children(self):
        """Test adding multiple child resources."""
        parent = Resource(kind="parent", name="parent")
        children = [
            Resource(kind="child", name=f"child_{i}")
            for i in range(5)
        ]

        for child in children:
            parent.add_child(child)

        assert len(parent.children) == 5

    def test_iter_single_resource(self):
        """Test iterating over a single resource."""
        resource = Resource(kind="test", name="test")

        items = list(resource.iter())

        assert len(items) == 1
        assert items[0] is resource

    def test_iter_with_children(self):
        """Test iterating over resource tree."""
        parent = Resource(kind="parent", name="parent")
        child1 = Resource(kind="child", name="child1")
        child2 = Resource(kind="child", name="child2")

        parent.add_child(child1)
        parent.add_child(child2)

        items = list(parent.iter())

        assert len(items) == 3
        assert items[0] is parent
        assert child1 in items
        assert child2 in items

    def test_iter_deep_hierarchy(self):
        """Test iterating over deeply nested hierarchy."""
        root = Resource(kind="root", name="root")
        level1 = Resource(kind="l1", name="level1")
        level2 = Resource(kind="l2", name="level2")
        level3 = Resource(kind="l3", name="level3")

        root.add_child(level1)
        level1.add_child(level2)
        level2.add_child(level3)

        items = list(root.iter())

        assert len(items) == 4
        names = [r.name for r in items]
        assert names == ["root", "level1", "level2", "level3"]

    def test_metadata_storage(self):
        """Test storing custom metadata."""
        resource = Resource(
            kind="test",
            name="test",
            metadata={"key1": "value1", "key2": 42},
        )

        assert resource.metadata["key1"] == "value1"
        assert resource.metadata["key2"] == 42


class TestBinaryResource:
    """Tests for BinaryResource class."""

    def test_create_binary_resource(self):
        """Test creating a binary resource."""
        binary = BinaryResource(
            kind="binary",
            name="test.elf",
            path="/tmp/test.elf",
            architecture="ARM64",
        )

        assert binary.kind == "binary"
        assert binary.name == "test.elf"
        assert binary.path == "/tmp/test.elf"
        assert binary.architecture == "ARM64"

    def test_binary_resource_default_values(self):
        """Test BinaryResource default values."""
        binary = BinaryResource(kind="binary", name="test")

        assert binary.path == ""
        assert binary.architecture is None

    def test_binary_with_function_children(self, sample_resource_tree):
        """Test binary resource with function children."""
        assert len(sample_resource_tree.children) == 2
        assert all(
            isinstance(child, FunctionResource)
            for child in sample_resource_tree.children
        )


class TestFunctionResource:
    """Tests for FunctionResource class."""

    def test_create_function_resource(self):
        """Test creating a function resource."""
        func = FunctionResource(
            kind="function",
            name="main",
            address=0x1000,
            size=256,
        )

        assert func.kind == "function"
        assert func.name == "main"
        assert func.address == 0x1000
        assert func.size == 256

    def test_function_resource_default_values(self):
        """Test FunctionResource default values."""
        func = FunctionResource(kind="function", name="unknown")

        assert func.address is None
        assert func.size is None

    def test_function_with_metadata(self):
        """Test function resource with metadata."""
        func = FunctionResource(
            kind="function",
            name="helper",
            address=0x2000,
            size=128,
            metadata={
                "nargs": 2,
                "nlocals": 4,
                "calling_convention": "cdecl",
            },
        )

        assert func.metadata["nargs"] == 2
        assert func.metadata["nlocals"] == 4
        assert func.metadata["calling_convention"] == "cdecl"


class TestInstructionResource:
    """Tests for InstructionResource class."""

    def test_create_instruction_resource(self):
        """Test creating an instruction resource."""
        insn = InstructionResource(
            kind="instruction",
            name="mov",
            address=0x1000,
            bytes_=b"\x04\xe0\x2d\xe5",
            mnemonic="push",
        )

        assert insn.kind == "instruction"
        assert insn.address == 0x1000
        assert insn.bytes_ == b"\x04\xe0\x2d\xe5"
        assert insn.mnemonic == "push"

    def test_instruction_resource_default_values(self):
        """Test InstructionResource default values."""
        insn = InstructionResource(kind="instruction", name="nop")

        assert insn.address is None
        assert insn.bytes_ is None
        assert insn.mnemonic is None

    def test_instruction_with_full_details(self):
        """Test instruction with all details."""
        insn = InstructionResource(
            kind="instruction",
            name="add r0, r1, r2",
            address=0x1004,
            bytes_=b"\x02\x00\x81\xe0",
            mnemonic="add",
            metadata={
                "operands": ["r0", "r1", "r2"],
                "flags_affected": ["N", "Z", "C", "V"],
            },
        )

        assert insn.metadata["operands"] == ["r0", "r1", "r2"]


class TestResourceTreeTraversal:
    """Tests for resource tree traversal patterns."""

    def test_find_functions_in_binary(self, sample_resource_tree):
        """Test finding all functions in a binary."""
        functions = [
            r for r in sample_resource_tree.iter()
            if isinstance(r, FunctionResource)
        ]

        assert len(functions) == 2
        names = {f.name for f in functions}
        assert "main" in names
        assert "helper" in names

    def test_find_by_kind(self, sample_resource_tree):
        """Test finding resources by kind."""
        binaries = [
            r for r in sample_resource_tree.iter()
            if r.kind == "binary"
        ]

        assert len(binaries) == 1

    def test_find_by_address(self, sample_resource_tree):
        """Test finding function by address."""
        target_address = 0x1000

        found = None
        for r in sample_resource_tree.iter():
            if isinstance(r, FunctionResource) and r.address == target_address:
                found = r
                break

        assert found is not None
        assert found.name == "main"

    def test_empty_tree_iteration(self, empty_resource_tree):
        """Test iterating over empty tree."""
        items = list(empty_resource_tree.iter())

        assert len(items) == 1
        assert items[0] is empty_resource_tree
