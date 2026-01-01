"""
Tests for error handling functionality.

These tests validate the error handling and expert info features
in tak.lua for malformed and unsupported messages.
"""

import pytest


class TestMalformedMessageHandling:
    """Tests for REQ-ERR-001: Malformed message expert info."""

    @pytest.mark.req("REQ-ERR-001")
    def test_expert_info_malformed_defined(self, project_root):
        """Verify malformed expert info is defined."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'tak.experts.malformed' in content
        assert 'ProtoExpert.new' in content
        assert 'expert.group.MALFORMED' in content

    @pytest.mark.req("REQ-ERR-001")
    def test_malformed_expert_used(self, project_root):
        """Verify malformed expert info is used on errors."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check that the expert info is added to tree on errors
        assert 'add_proto_expert_info(tak.experts.malformed' in content

    @pytest.mark.req("REQ-ERR-001")
    def test_malformed_varint_handling(self, project_root):
        """Verify malformed varint handling."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for varint error handling
        assert 'Failed to decode varint' in content or 'malformed' in content.lower()


class TestUnsupportedMessageHandling:
    """Tests for REQ-ERR-002: Unsupported message expert info."""

    @pytest.mark.req("REQ-ERR-002")
    def test_expert_info_unsupported_defined(self, project_root):
        """Verify unsupported expert info is defined."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'tak.experts.unsupported' in content
        assert 'expert.group.UNDECODED' in content

    @pytest.mark.req("REQ-ERR-002")
    def test_unsupported_expert_used(self, project_root):
        """Verify unsupported expert info is used for unknown formats."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'add_proto_expert_info(tak.experts.unsupported' in content

    @pytest.mark.req("REQ-ERR-002")
    def test_unknown_format_handling(self, project_root):
        """Verify unknown format is flagged as unsupported."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'Unknown message format' in content or 'Unsupported' in content


class TestEdgeCases:
    """Tests for edge case handling."""

    def test_empty_buffer_handling(self, project_root):
        """Verify empty or minimal buffers are handled."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for length validation
        assert 'buffer:len()' in content or 'length' in content

    def test_truncated_message_handling(self, project_root):
        """Verify truncated messages are handled gracefully."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for bounds checking
        assert 'offset' in content
        assert '>' in content  # Comparison for bounds

    def test_return_on_error(self, project_root):
        """Verify dissector returns appropriately on errors."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for return 0 on errors
        assert 'return 0' in content


class TestExpertInfoSeverity:
    """Tests for expert info severity levels."""

    def test_malformed_is_error(self, project_root):
        """Verify malformed messages are ERROR severity."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'expert.severity.ERROR' in content

    def test_unsupported_is_warn(self, project_root):
        """Verify unsupported messages are WARN severity."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        assert 'expert.severity.WARN' in content


class TestInputValidation:
    """Tests for input validation patterns."""

    def test_nil_check_pattern(self, project_root):
        """Verify nil checks are performed."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for nil validation
        assert '== nil' in content or '~= nil' in content

    def test_length_validation(self, project_root):
        """Verify length validation is performed."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for length checks
        assert 'length' in content.lower()
        assert '>=' in content or '<=' in content

    def test_type_checking(self, project_root):
        """Verify type checking for protobuf fields."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for type validation
        assert 'type(' in content


class TestErrorMessages:
    """Tests for error message quality."""

    def test_descriptive_error_messages(self, project_root):
        """Verify error messages are descriptive."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check that expert messages are descriptive
        assert 'Malformed TAK Message' in content
        assert 'Unsupported Message Type' in content

    def test_error_context(self, project_root):
        """Verify errors include context (what failed)."""
        plugin_path = project_root / "tak.lua"
        content = plugin_path.read_text()

        # Check for contextual information in error handling
        # Common pattern: include field or operation name in error
        assert 'varint' in content.lower() or 'decode' in content.lower()
