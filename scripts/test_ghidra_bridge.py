#!/usr/bin/env python3
"""Test script for Ghidra bridge connectivity and functionality.

This script verifies that the Ghidra bridge server is running and can
provide decompiled function data.

Usage:
    # Start Ghidra with a binary loaded, then run the bridge server script:
    # In Ghidra's Script Manager, run ghidra_bridge_server_background.py

    # Then run this test:
    python scripts/test_ghidra_bridge.py

    # Or with a specific binary path to verify:
    python scripts/test_ghidra_bridge.py samples/bin/arm64/hello
"""

import argparse
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_bridge_connectivity(host: str, port: int, timeout: int) -> bool:
    """Test basic bridge connectivity."""
    print(f"\n[1] Testing connection to Ghidra bridge at {host}:{port}...")

    try:
        from r2d2.adapters.ghidra_bridge_client import GhidraBridgeClient

        client = GhidraBridgeClient(host=host, port=port, timeout=timeout)

        if client.connect():
            print("    ✓ Successfully connected to Ghidra bridge")
            return True
        else:
            print("    ✗ Failed to connect to Ghidra bridge")
            return False

    except ImportError as e:
        print(f"    ✗ ghidra_bridge module not installed: {e}")
        print("    Install with: pip install ghidra_bridge")
        return False
    except Exception as e:
        print(f"    ✗ Connection error: {e}")
        return False


def test_program_info(client) -> dict | None:
    """Test getting current program information."""
    print("\n[2] Getting current program information...")

    try:
        program_name = client.get_current_program_name()
        program_path = client.get_current_program_path()

        if program_name:
            print(f"    ✓ Program name: {program_name}")
            print(f"    ✓ Program path: {program_path}")
            return {"name": program_name, "path": program_path}
        else:
            print("    ✗ No program loaded in Ghidra")
            return None

    except Exception as e:
        print(f"    ✗ Error getting program info: {e}")
        return None


def test_functions(client, limit: int = 10) -> list:
    """Test getting function list."""
    print(f"\n[3] Getting function list (limit {limit})...")

    try:
        functions = client.get_functions(limit=limit)

        if functions:
            print(f"    ✓ Retrieved {len(functions)} functions")
            for i, func in enumerate(functions[:5]):
                name = func.get("name", "unknown")
                addr = func.get("address", 0)
                size = func.get("size", 0)
                print(f"       [{i+1}] {name} @ 0x{addr:x} (size: {size})")
            if len(functions) > 5:
                print(f"       ... and {len(functions) - 5} more")
            return functions
        else:
            print("    ✗ No functions found")
            return []

    except Exception as e:
        print(f"    ✗ Error getting functions: {e}")
        return []


def test_decompilation(client, functions: list, limit: int = 3) -> list:
    """Test decompilation of functions."""
    print(f"\n[4] Testing decompilation (limit {limit})...")

    if not functions:
        print("    ✗ No functions available for decompilation")
        return []

    try:
        addresses = [f["address"] for f in functions[:limit] if "address" in f]
        decompiled = client.batch_decompile(addresses, limit=limit)

        if decompiled:
            print(f"    ✓ Decompiled {len(decompiled)} functions")
            for i, func in enumerate(decompiled[:2]):
                print(f"\n    --- {func.name} @ 0x{func.address:x} ---")
                # Show first few lines of decompiled code
                lines = func.decompiled_c.split("\n")[:8]
                for line in lines:
                    print(f"    {line}")
                if len(func.decompiled_c.split("\n")) > 8:
                    print("    ...")
            return decompiled
        else:
            print("    ✗ Decompilation failed")
            return []

    except Exception as e:
        print(f"    ✗ Error during decompilation: {e}")
        return []


def test_types(client, limit: int = 10) -> list:
    """Test getting type information."""
    print(f"\n[5] Getting type information (limit {limit})...")

    try:
        types = client.get_types(limit=limit)

        if types:
            print(f"    ✓ Retrieved {len(types)} types")
            # Show structs first as they're most useful
            structs = [t for t in types if t.kind == "struct"]
            for i, t in enumerate(structs[:3]):
                print(f"       struct {t.name} ({t.size} bytes)")
                for member in t.members[:3]:
                    print(f"         {member.get('name', '?')}: {member.get('type', '?')}")
                if len(t.members) > 3:
                    print(f"         ... and {len(t.members) - 3} more members")
            return types
        else:
            print("    ✗ No types found")
            return []

    except Exception as e:
        print(f"    ✗ Error getting types: {e}")
        return []


def test_strings(client, limit: int = 10) -> list:
    """Test getting string data."""
    print(f"\n[6] Getting strings (limit {limit})...")

    try:
        strings = client.get_strings(limit=limit)

        if strings:
            print(f"    ✓ Retrieved {len(strings)} strings")
            for i, s in enumerate(strings[:5]):
                addr = s.get("address", 0)
                value = s.get("value", "")
                # Truncate long strings
                if len(value) > 50:
                    value = value[:50] + "..."
                print(f"       0x{addr:x}: \"{value}\"")
            return strings
        else:
            print("    ✗ No strings found")
            return []

    except Exception as e:
        print(f"    ✗ Error getting strings: {e}")
        return []


def test_xrefs(client, functions: list) -> dict:
    """Test cross-reference functionality."""
    print("\n[7] Testing cross-references...")

    if not functions:
        print("    ✗ No functions available for xref testing")
        return {}

    try:
        # Get xrefs for first function
        func = functions[0]
        addr = func.get("address", 0)
        name = func.get("name", "unknown")

        to_refs = client.get_xrefs_to(addr)
        from_refs = client.get_xrefs_from(addr)

        print(f"    ✓ {name} @ 0x{addr:x}")
        print(f"       References TO: {len(to_refs)}")
        for ref in to_refs[:3]:
            print(f"         from 0x{ref.from_address:x} ({ref.ref_type})")

        print(f"       References FROM: {len(from_refs)}")
        for ref in from_refs[:3]:
            print(f"         to 0x{ref.to_address:x} ({ref.ref_type})")

        return {"to": to_refs, "from": from_refs}

    except Exception as e:
        print(f"    ✗ Error getting xrefs: {e}")
        return {}


def main():
    parser = argparse.ArgumentParser(description="Test Ghidra bridge connectivity")
    parser.add_argument("binary", nargs="?", help="Optional binary path to verify is loaded")
    parser.add_argument("--host", default="127.0.0.1", help="Bridge host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=13100, help="Bridge port (default: 13100)")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds (default: 30)")
    args = parser.parse_args()

    print("=" * 60)
    print("Ghidra Bridge Test Script")
    print("=" * 60)

    # Test connectivity
    from r2d2.adapters.ghidra_bridge_client import GhidraBridgeClient

    client = GhidraBridgeClient(host=args.host, port=args.port, timeout=args.timeout)

    if not client.connect():
        print("\n✗ FAILED: Could not connect to Ghidra bridge")
        print("\nMake sure:")
        print("  1. Ghidra is running with a binary loaded")
        print("  2. The bridge server script is running in Ghidra")
        print("     (Run ghidra_bridge_server_background.py from Script Manager)")
        print(f"  3. The bridge is listening on {args.host}:{args.port}")
        sys.exit(1)

    print("    ✓ Connected to Ghidra bridge")

    # Test program info
    program_info = test_program_info(client)
    if not program_info:
        print("\n⚠ WARNING: No program loaded in Ghidra")

    # Verify binary if specified
    if args.binary and program_info:
        binary_path = Path(args.binary).resolve()
        if client.is_binary_loaded(binary_path):
            print(f"\n    ✓ Verified: {args.binary} is loaded")
        else:
            print(f"\n    ⚠ WARNING: Expected binary not loaded")
            print(f"      Expected: {binary_path}")
            print(f"      Loaded:   {program_info.get('path')}")

    # Test functions
    functions = test_functions(client)

    # Test decompilation
    decompiled = test_decompilation(client, functions)

    # Test types
    types = test_types(client)

    # Test strings
    strings = test_strings(client)

    # Test xrefs
    xrefs = test_xrefs(client, functions)

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"  Connection:     ✓ OK")
    print(f"  Program loaded: {'✓' if program_info else '✗'} {program_info.get('name', 'None') if program_info else ''}")
    print(f"  Functions:      {'✓' if functions else '✗'} {len(functions)} found")
    print(f"  Decompilation:  {'✓' if decompiled else '✗'} {len(decompiled)} functions")
    print(f"  Types:          {'✓' if types else '✗'} {len(types)} types")
    print(f"  Strings:        {'✓' if strings else '✗'} {len(strings)} strings")
    print(f"  Cross-refs:     {'✓' if xrefs else '✗'}")

    all_passed = all([program_info, functions, decompiled])
    if all_passed:
        print("\n✓ All tests passed! Ghidra bridge is working correctly.")
    else:
        print("\n⚠ Some tests failed. Check the output above for details.")

    # Disconnect
    client.disconnect()
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
