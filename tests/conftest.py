"""
Pytest configuration and fixtures for TAK Wireshark Plugin tests.

These tests validate the Lua dissector by:
1. Executing actual Lua code via lupa bridge
2. Testing XML CoT message parsing with real examples
3. Testing protobuf parsing with binary fixtures
"""

import sys
import pytest
from pathlib import Path

# Add tests directory to path for lua_bridge import
sys.path.insert(0, str(Path(__file__).parent))

from lua_bridge import get_bridge, get_omni_bridge, reset_bridge, LuaBridge, OmniBridge

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"
TAKCOT_EXAMPLES = FIXTURES_DIR / "cot_examples"
OMNI_TEST_ASSETS = FIXTURES_DIR / "omni_assets"


def pytest_configure(config):
    """Register custom markers for RTMX integration."""
    config.addinivalue_line("markers", "req(req_id): Link test to requirement ID")


@pytest.fixture
def project_root():
    """Return the project root directory."""
    return PROJECT_ROOT


@pytest.fixture
def fixtures_dir():
    """Return the test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def takcot_examples():
    """Return path to TAK CoT XML examples."""
    return TAKCOT_EXAMPLES


@pytest.fixture
def omni_test_assets():
    """Return path to OMNI binary test assets."""
    return OMNI_TEST_ASSETS


@pytest.fixture
def marker_spot_xml():
    """Load Marker - Spot.cot XML example."""
    path = TAKCOT_EXAMPLES / "Marker - Spot.cot"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


@pytest.fixture
def marker_2525_xml():
    """Load Marker - 2525.cot XML example."""
    path = TAKCOT_EXAMPLES / "Marker - 2525.cot"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


@pytest.fixture
def route_xml():
    """Load Route.cot XML example."""
    path = TAKCOT_EXAMPLES / "Route.cot"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


@pytest.fixture
def circle_xml():
    """Load Drawing Shapes - Circle.cot XML example."""
    path = TAKCOT_EXAMPLES / "Drawing Shapes - Circle.cot"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


@pytest.fixture
def geofence_xml():
    """Load Geo Fence.cot XML example."""
    path = TAKCOT_EXAMPLES / "Geo Fence.cot"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


@pytest.fixture
def omni_player_event_bin():
    """Load OMNI PlayerEvent binary test fixture."""
    path = OMNI_TEST_ASSETS / "test_playerevent.bin"
    if path.exists():
        return path.read_bytes()
    return None


# Sample protobuf test data
@pytest.fixture
def tak_stream_sample():
    """
    Sample TAK Stream protocol message (version 1).
    Format: 0xBF + varint_length + TakMessage
    """
    # Minimal TakMessage with CotEvent containing type and uid
    # Field 2 (CotEvent) with nested fields
    return bytes([
        0xBF,  # Magic byte
        0x1E,  # Length varint (30 bytes)
        # TakMessage field 2 (CotEvent)
        0x12, 0x1C,  # Tag 2, length 28
        # CotEvent field 1 (type) = "a-f-G"
        0x0A, 0x05, 0x61, 0x2D, 0x66, 0x2D, 0x47,
        # CotEvent field 5 (uid) = "test-uid-123"
        0x2A, 0x0C, 0x74, 0x65, 0x73, 0x74, 0x2D, 0x75, 0x69, 0x64, 0x2D, 0x31, 0x32, 0x33,
        # CotEvent field 9 (how) = "m-g"
        0x4A, 0x03, 0x6D, 0x2D, 0x67,
    ])


@pytest.fixture
def tak_mesh_sample():
    """
    Sample TAK Mesh protocol message (version 2+).
    Format: 0xBF + version_varint + 0xBF + TakMessage
    """
    # Version 2 mesh message with minimal CotEvent
    return bytes([
        0xBF,  # First magic byte
        0x02,  # Version varint (2)
        0xBF,  # Second magic byte
        # TakMessage field 2 (CotEvent)
        0x12, 0x10,  # Tag 2, length 16
        # CotEvent field 1 (type) = "a-u-G"
        0x0A, 0x05, 0x61, 0x2D, 0x75, 0x2D, 0x47,
        # CotEvent field 5 (uid) = "mesh-test"
        0x2A, 0x09, 0x6D, 0x65, 0x73, 0x68, 0x2D, 0x74, 0x65, 0x73, 0x74,
    ])


@pytest.fixture
def varint_test_cases():
    """Test cases for varint decoding."""
    return [
        # (bytes, expected_value, expected_bytes_consumed)
        (bytes([0x00]), 0, 1),
        (bytes([0x01]), 1, 1),
        (bytes([0x7F]), 127, 1),
        (bytes([0x80, 0x01]), 128, 2),
        (bytes([0xFF, 0x01]), 255, 2),
        (bytes([0xAC, 0x02]), 300, 2),
        (bytes([0x96, 0x01]), 150, 2),
        (bytes([0x80, 0x80, 0x01]), 16384, 3),
    ]


# =========================================================================
# Lua Bridge Fixtures
# =========================================================================

@pytest.fixture(scope="session")
def lua_bridge() -> LuaBridge:
    """
    Provide a Lua bridge instance for testing actual Lua code.

    This fixture loads tak.lua via lupa and provides access to the
    pb (protobuf) and xml modules for direct testing.
    """
    return get_bridge()


@pytest.fixture
def pb(lua_bridge: LuaBridge) -> LuaBridge:
    """Shorthand fixture for protobuf testing via Lua bridge."""
    return lua_bridge


@pytest.fixture
def xml_parser(lua_bridge: LuaBridge) -> LuaBridge:
    """Shorthand fixture for XML parser testing via Lua bridge."""
    return lua_bridge


@pytest.fixture(scope="session")
def omni_bridge() -> OmniBridge:
    """
    Provide an OMNI Lua bridge instance for testing actual Lua code.

    This fixture loads omni.lua via lupa and provides access to the
    pb (protobuf) module for direct testing.
    """
    return get_omni_bridge()


@pytest.fixture
def omni_pb(omni_bridge: OmniBridge) -> OmniBridge:
    """Shorthand fixture for OMNI protobuf testing via Lua bridge."""
    return omni_bridge
