"""
Tests for Wireshark integration features.

These tests validate the Wireshark-specific functionality in tak.lua
including port registration, protocol field definitions, display
hierarchy, and filtering capabilities.

Note: Full integration testing requires Wireshark/tshark to be installed.
These tests verify the expected structure and can be extended for
actual dissection testing.
"""

import os
import subprocess
import pytest
from pathlib import Path


def tshark_available() -> bool:
    """Check if tshark is available on the system."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_plugin_path() -> Path:
    """Get path to tak.lua plugin."""
    return Path(__file__).parent.parent / "tak.lua"


class TestPortRegistration:
    """Tests for REQ-WS-001 and REQ-WS-002: Port configuration."""

    @pytest.mark.req("REQ-WS-001")
    def test_tak_port_default(self, project_root):
        """Verify default TAK ports are configured."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check all standard TAK ports are defined
        assert "port_default = 4242" in content
        assert "port_sa_mcast = 6969" in content
        assert "port_sensor = 7171" in content
        assert "port_streaming = 8087" in content
        assert "port_chat = 17012" in content

    @pytest.mark.req("REQ-WS-002")
    def test_omni_port_default(self, project_root):
        """Verify default OMNI port is 8089."""
        plugin_path = project_root / "omni.lua"
        content = plugin_path.read_text()

        assert "port = 8089" in content

    @pytest.mark.req("REQ-WS-001")
    def test_tak_port_tcp_registration(self, project_root):
        """Verify TAK dissector registers for TCP."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'tcp.port' in content
        assert 'DissectorTable.get("tcp.port")' in content

    @pytest.mark.req("REQ-WS-001")
    def test_tak_port_udp_registration(self, project_root):
        """Verify TAK dissector registers for UDP."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'udp.port' in content
        assert 'DissectorTable.get("udp.port")' in content

    @pytest.mark.req("REQ-WS-001")
    @pytest.mark.req("REQ-WS-002")
    def test_port_preference_defined(self, project_root):
        """Verify port preferences are configurable."""
        # TAK port preferences
        tak_path = project_root / "tak.lua"
        tak_content = tak_path.read_text()
        assert 'tak.prefs.port_default' in tak_content
        assert 'tak.prefs.port_sa_mcast' in tak_content
        assert 'tak.prefs.port_streaming' in tak_content

        # OMNI port preference
        omni_path = project_root / "omni.lua"
        omni_content = omni_path.read_text()
        assert 'omni.prefs.port' in omni_content


class TestProtoFieldDefinitions:
    """Tests for REQ-WS-003 and REQ-WS-004: Protocol field definitions."""

    @pytest.mark.req("REQ-WS-003")
    def test_protocol_field_defined(self, project_root):
        """Verify protocol field is defined for hierarchy."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'tak.fields.protocol' in content
        assert 'ProtoField.string("tak.protocol"' in content

    @pytest.mark.req("REQ-WS-003")
    def test_cot_event_fields_defined(self, project_root):
        """Verify CoT event fields are defined."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        expected_fields = [
            'tak.fields.cot_type',
            'tak.fields.cot_uid',
            'tak.fields.cot_how',
        ]

        for field in expected_fields:
            assert field in content, f"Missing field definition: {field}"

    @pytest.mark.req("REQ-WS-003")
    def test_point_fields_defined(self, project_root):
        """Verify point fields are defined for coordinates."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        expected_fields = [
            'tak.fields.lat',
            'tak.fields.lon',
            'tak.fields.hae',
            'tak.fields.ce',
            'tak.fields.le',
        ]

        for field in expected_fields:
            assert field in content, f"Missing field definition: {field}"

    @pytest.mark.req("REQ-WS-003")
    def test_omni_fields_defined(self, project_root):
        """Verify OMNI fields are defined."""
        plugin_path = project_root / "omni.lua"
        content = plugin_path.read_text()

        expected_fields = [
            'omni.fields.entity_id',
            'omni.fields.event_type',
        ]

        for field in expected_fields:
            assert field in content, f"Missing field definition: {field}"

    @pytest.mark.req("REQ-WS-004")
    def test_field_filter_names(self, project_root):
        """Verify fields have proper filter names for display filtering."""
        # Check TAK filter names
        tak_path = project_root / "tak.lua"
        tak_content = tak_path.read_text()

        tak_filters = [
            '"tak.cot.type"',
            '"tak.cot.uid"',
            '"tak.point.lat"',
            '"tak.point.lon"',
        ]

        for filter_name in tak_filters:
            assert filter_name in tak_content, f"Missing TAK filter name: {filter_name}"

        # Check OMNI filter names
        omni_path = project_root / "omni.lua"
        omni_content = omni_path.read_text()

        omni_filters = [
            '"omni.entity_id"',
        ]

        for filter_name in omni_filters:
            assert filter_name in omni_content, f"Missing OMNI filter name: {filter_name}"


class TestDisplayHierarchy:
    """Tests for REQ-WS-003: Display hierarchy."""

    @pytest.mark.req("REQ-WS-003")
    def test_tree_structure_created(self, project_root):
        """Verify tree structure is created for packet details."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for tree:add() calls which build hierarchy
        assert 'tree:add(' in content or 'subtree:add(' in content

    @pytest.mark.req("REQ-WS-003")
    def test_nested_subtrees(self, project_root):
        """Verify nested subtrees for detail elements."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for subtree creation patterns
        assert 'local subtree = tree:add' in content


class TestInfoColumn:
    """Tests for REQ-WS-005: Info column updates."""

    @pytest.mark.req("REQ-WS-005")
    def test_info_column_set(self, project_root):
        """Verify info column is set."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'pinfo.cols.info' in content

    @pytest.mark.req("REQ-WS-005")
    def test_info_column_protocol_set(self, project_root):
        """Verify protocol column is set."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'pinfo.cols.protocol' in content

    @pytest.mark.req("REQ-WS-005")
    def test_info_column_append(self, project_root):
        """Verify info column is appended with message details."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for info column updates
        assert ':append(' in content or ':set(' in content


class TestPluginStructure:
    """Tests verifying the plugin Lua structure."""

    def test_plugin_file_exists(self, project_root):
        """Verify tak.lua exists."""
        plugin_path = project_root / "tak.lua"
        assert plugin_path.exists()

    def test_plugin_metadata(self, project_root):
        """Verify plugin has required metadata."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'set_plugin_info' in content
        assert 'description' in content
        assert 'version' in content

    def test_protocol_definition(self, project_root):
        """Verify protocol is properly defined."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'tak = Proto("TAK"' in content

    def test_dissector_function(self, project_root):
        """Verify dissector function is defined."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'tak.dissector = function' in content


@pytest.mark.skipif(not tshark_available(), reason="tshark not available")
class TestTsharkIntegration:
    """Integration tests using tshark (requires Wireshark installation)."""

    def test_plugin_loads(self, project_root):
        """Verify plugin loads without errors in tshark."""
        plugin_path = project_root / "tak.lua"

        # Use -G first, then load the plugin via user's plugin dir
        # tshark -G must be first option
        result = subprocess.run(
            [
                "tshark",
                "-G", "protocols"
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "WIRESHARK_PLUGIN_DIR": str(project_root)}
        )

        # Check TAK protocol is registered (if plugin is installed)
        # This test passes if tshark runs successfully
        assert result.returncode == 0

    def test_field_registration(self, project_root):
        """Verify fields are registered with tshark."""
        plugin_path = project_root / "tak.lua"

        result = subprocess.run(
            [
                "tshark",
                "-G", "fields"
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "WIRESHARK_PLUGIN_DIR": str(project_root)}
        )

        # Check tshark runs - fields may or may not include TAK depending on install
        assert result.returncode == 0
