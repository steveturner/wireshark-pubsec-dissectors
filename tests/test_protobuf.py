"""
Tests for native Protobuf decoder implementation.

These tests validate the actual protobuf decoding logic in tak.lua's pb module
by executing the real Lua code via the lupa bridge. This ensures the tests
exercise the same code that runs in Wireshark.
"""

import struct
import sys
from pathlib import Path

import pytest

# Ensure lua_bridge can be imported
sys.path.insert(0, str(Path(__file__).parent))
from lua_bridge import LuaBridge


class TestVarintDecoding:
    """Tests for REQ-PB-001: Varint decoding via actual Lua code."""

    @pytest.mark.req("REQ-PB-001")
    def test_decode_varint_single_byte(self, pb: LuaBridge):
        """Verify single-byte varints are decoded correctly by Lua."""
        assert pb.decode_varint(bytes([0x00])) == (0, 1)
        assert pb.decode_varint(bytes([0x01])) == (1, 1)
        assert pb.decode_varint(bytes([0x7F])) == (127, 1)

    @pytest.mark.req("REQ-PB-001")
    def test_decode_varint_multi_byte(self, pb: LuaBridge):
        """Verify multi-byte varints are decoded correctly by Lua."""
        assert pb.decode_varint(bytes([0x80, 0x01])) == (128, 2)
        assert pb.decode_varint(bytes([0xFF, 0x01])) == (255, 2)
        assert pb.decode_varint(bytes([0xAC, 0x02])) == (300, 2)
        assert pb.decode_varint(bytes([0x96, 0x01])) == (150, 2)

    @pytest.mark.req("REQ-PB-001")
    def test_decode_varint_three_bytes(self, pb: LuaBridge):
        """Verify three-byte varints are decoded correctly by Lua."""
        assert pb.decode_varint(bytes([0x80, 0x80, 0x01])) == (16384, 3)

    @pytest.mark.req("REQ-PB-001")
    def test_decode_varint_with_offset(self, pb: LuaBridge):
        """Verify varints can be decoded at offset by Lua."""
        data = bytes([0xFF, 0xFF, 0xAC, 0x02])
        assert pb.decode_varint(data, 2) == (300, 2)

    @pytest.mark.req("REQ-PB-001")
    def test_decode_varint_insufficient_data(self, pb: LuaBridge):
        """Verify error handling for incomplete varints in Lua."""
        # Continuation bit set but no more bytes
        result = pb.decode_varint(bytes([0x80]))
        assert result[0] is None or result[1] == 0

    @pytest.mark.req("REQ-PB-001")
    def test_decode_varint_test_cases(self, pb: LuaBridge, varint_test_cases):
        """Verify all varint test cases from fixture via Lua."""
        for data, expected_value, expected_bytes in varint_test_cases:
            value, bytes_consumed = pb.decode_varint(data)
            assert value == expected_value, f"Expected {expected_value}, got {value}"
            assert bytes_consumed == expected_bytes

    @pytest.mark.req("REQ-PB-001")
    def test_decode_sint_positive(self, pb: LuaBridge):
        """Verify signed varint (zigzag) decoding for positive numbers via Lua."""
        # Zigzag encoding: 0->0, 1->2, 2->4, etc.
        assert pb.decode_sint(bytes([0x00])) == (0, 1)  # 0 encodes to 0
        assert pb.decode_sint(bytes([0x02])) == (1, 1)  # 1 encodes to 2
        assert pb.decode_sint(bytes([0x04])) == (2, 1)  # 2 encodes to 4

    @pytest.mark.req("REQ-PB-001")
    def test_decode_sint_negative(self, pb: LuaBridge):
        """Verify signed varint (zigzag) decoding for negative numbers via Lua."""
        # Zigzag encoding: -1->1, -2->3, etc.
        assert pb.decode_sint(bytes([0x01])) == (-1, 1)  # -1 encodes to 1
        assert pb.decode_sint(bytes([0x03])) == (-2, 1)  # -2 encodes to 3


class TestDoubleDecoding:
    """Tests for REQ-PB-002: 64-bit fixed (double) decoding via actual Lua code."""

    @pytest.mark.req("REQ-PB-002")
    def test_decode_double_zero(self, pb: LuaBridge):
        """Verify zero is decoded correctly by Lua."""
        data = struct.pack("<d", 0.0)
        value, consumed = pb.decode_double(data)
        assert consumed == 8
        assert value == 0.0

    @pytest.mark.req("REQ-PB-002")
    def test_decode_double_coordinate(self, pb: LuaBridge):
        """Verify coordinate-like double is decoded correctly by Lua."""
        lat = 38.85606343062312
        data = struct.pack("<d", lat)
        value, consumed = pb.decode_double(data)
        assert consumed == 8
        assert value == pytest.approx(lat, rel=1e-10)

    @pytest.mark.req("REQ-PB-002")
    def test_decode_double_negative(self, pb: LuaBridge):
        """Verify negative double is decoded correctly by Lua."""
        lon = -77.0563755018233
        data = struct.pack("<d", lon)
        value, consumed = pb.decode_double(data)
        assert consumed == 8
        assert value == pytest.approx(lon, rel=1e-10)

    @pytest.mark.req("REQ-PB-002")
    def test_decode_fixed64_unsigned(self, pb: LuaBridge):
        """Verify 64-bit unsigned integer is decoded by Lua."""
        timestamp = 1608148774913  # milliseconds since epoch
        data = struct.pack("<Q", timestamp)
        value, consumed = pb.decode_fixed64(data)
        assert consumed == 8
        assert value == pytest.approx(timestamp, rel=1e-10)

    @pytest.mark.req("REQ-PB-002")
    def test_decode_fixed32(self, pb: LuaBridge):
        """Verify 32-bit fixed integer is decoded by Lua."""
        test_val = 12345678
        data = struct.pack("<I", test_val)
        value, consumed = pb.decode_fixed32(data)
        assert consumed == 4
        assert value == test_val

    @pytest.mark.req("REQ-PB-002")
    def test_decode_float(self, pb: LuaBridge):
        """Verify 32-bit float is decoded by Lua."""
        test_val = 3.14159
        data = struct.pack("<f", test_val)
        value, consumed = pb.decode_float(data)
        assert consumed == 4
        assert value == pytest.approx(test_val, rel=1e-5)


class TestLengthDelimitedDecoding:
    """Tests for REQ-PB-003: Length-delimited field decoding via actual Lua code."""

    @pytest.mark.req("REQ-PB-003")
    def test_decode_string(self, pb: LuaBridge):
        """Verify string decoding (length-delimited) by Lua."""
        # String "a-f-G" with length prefix
        string_bytes = b"a-f-G"
        data = bytes([len(string_bytes)]) + string_bytes

        field_data, length, total = pb.decode_length_delimited(data)
        assert length == 5
        assert total == 6  # 1 byte length + 5 bytes data
        assert field_data == b"a-f-G"

    @pytest.mark.req("REQ-PB-003")
    def test_decode_long_string(self, pb: LuaBridge):
        """Verify longer string with multi-byte length varint by Lua."""
        string_bytes = b"test-uid-" + b"x" * 200
        length_varint = bytes([0xD1, 0x01])  # 209 in varint
        data = length_varint + string_bytes

        field_data, length, total = pb.decode_length_delimited(data)
        assert length == 209
        assert total == 211  # 2 byte length + 209 bytes data
        assert field_data == string_bytes

    @pytest.mark.req("REQ-PB-003")
    def test_decode_embedded_message(self, pb: LuaBridge):
        """Verify embedded message decoding by Lua."""
        # Embedded message with field 1 (string "test")
        inner_message = bytes([0x0A, 0x04, 0x74, 0x65, 0x73, 0x74])
        data = bytes([len(inner_message)]) + inner_message

        field_data, length, total = pb.decode_length_delimited(data)
        assert length == 6
        assert field_data == inner_message

    @pytest.mark.req("REQ-PB-003")
    def test_decode_insufficient_data(self, pb: LuaBridge):
        """Verify error handling when data is truncated by Lua."""
        # Says length is 10 but only 5 bytes follow
        data = bytes([10, 1, 2, 3, 4, 5])
        field_data, length, total = pb.decode_length_delimited(data)
        assert field_data is None
        assert total == 0


class TestTagDecoding:
    """Tests for REQ-PB-004: Field tag decoding via actual Lua code."""

    @pytest.mark.req("REQ-PB-004")
    def test_decode_tag_varint(self, pb: LuaBridge):
        """Verify tag decoding for varint wire type by Lua."""
        # Field 1, wire type 0 (varint) -> tag = (1 << 3) | 0 = 0x08
        field_num, wire_type, consumed = pb.decode_tag(bytes([0x08]))
        assert field_num == 1
        assert wire_type == pb.WIRE_VARINT
        assert consumed == 1

    @pytest.mark.req("REQ-PB-004")
    def test_decode_tag_64bit(self, pb: LuaBridge):
        """Verify tag decoding for 64-bit wire type by Lua."""
        # Field 10, wire type 1 (64-bit) -> tag = (10 << 3) | 1 = 0x51
        field_num, wire_type, consumed = pb.decode_tag(bytes([0x51]))
        assert field_num == 10
        assert wire_type == pb.WIRE_64BIT
        assert consumed == 1

    @pytest.mark.req("REQ-PB-004")
    def test_decode_tag_length_delimited(self, pb: LuaBridge):
        """Verify tag decoding for length-delimited wire type by Lua."""
        # Field 2, wire type 2 (length-delimited) -> tag = (2 << 3) | 2 = 0x12
        field_num, wire_type, consumed = pb.decode_tag(bytes([0x12]))
        assert field_num == 2
        assert wire_type == pb.WIRE_LENGTH_DELIMITED
        assert consumed == 1

    @pytest.mark.req("REQ-PB-004")
    def test_decode_tag_32bit(self, pb: LuaBridge):
        """Verify tag decoding for 32-bit wire type by Lua."""
        # Field 1, wire type 5 (32-bit) -> tag = (1 << 3) | 5 = 0x0D
        field_num, wire_type, consumed = pb.decode_tag(bytes([0x0D]))
        assert field_num == 1
        assert wire_type == pb.WIRE_32BIT
        assert consumed == 1

    @pytest.mark.req("REQ-PB-004")
    def test_decode_tag_high_field_number(self, pb: LuaBridge):
        """Verify tag decoding for field number > 15 (multi-byte tag) by Lua."""
        # Field 100, wire type 2 -> tag = (100 << 3) | 2 = 802 = 0xA2 0x06
        field_num, wire_type, consumed = pb.decode_tag(bytes([0xA2, 0x06]))
        assert field_num == 100
        assert wire_type == pb.WIRE_LENGTH_DELIMITED
        assert consumed == 2


class TestMessageParsing:
    """Tests for complete message parsing via actual Lua code."""

    @pytest.mark.req("REQ-PB-005")
    def test_parse_simple_message(self, pb: LuaBridge):
        """Verify parsing a simple protobuf message by Lua."""
        # Message with:
        # - Field 1 (string) = "test"
        # - Field 2 (varint) = 42
        message = bytes([
            0x0A, 0x04, 0x74, 0x65, 0x73, 0x74,  # Field 1: string "test"
            0x10, 0x2A,  # Field 2: varint 42
        ])

        fields = pb.parse_message(message)

        # Verify field 1 (string)
        assert 1 in fields
        assert fields[1]['wire_type'] == pb.WIRE_LENGTH_DELIMITED
        assert "test" in str(fields[1]['values'][0])

        # Verify field 2 (varint)
        assert 2 in fields
        assert fields[2]['wire_type'] == pb.WIRE_VARINT
        assert fields[2]['values'][0] == 42

    @pytest.mark.req("REQ-PB-005")
    def test_parse_message_with_doubles(self, pb: LuaBridge):
        """Verify parsing a message with double fields by Lua."""
        lat = 38.85606343062312
        lon = -77.0563755018233

        # Build message with:
        # - Field 10 (lat) = double
        # - Field 11 (lon) = double
        message = (
            bytes([0x51]) + struct.pack("<d", lat) +   # Field 10 (lat)
            bytes([0x59]) + struct.pack("<d", lon)     # Field 11 (lon)
        )

        fields = pb.parse_message(message)

        assert 10 in fields
        assert fields[10]['wire_type'] == pb.WIRE_64BIT

        assert 11 in fields
        assert fields[11]['wire_type'] == pb.WIRE_64BIT

    @pytest.mark.req("REQ-PB-005")
    def test_parse_nested_message(self, pb: LuaBridge):
        """Verify parsing nested protobuf messages by Lua."""
        # Inner message: field 1 (string) = "inner"
        inner = bytes([0x0A, 0x05]) + b"inner"

        # Outer message: field 1 (embedded message)
        message = bytes([0x0A, len(inner)]) + inner

        fields = pb.parse_message(message)

        assert 1 in fields
        assert fields[1]['wire_type'] == pb.WIRE_LENGTH_DELIMITED

    @pytest.mark.req("REQ-PB-006")
    def test_parse_repeated_fields(self, pb: LuaBridge):
        """Verify parsing repeated fields by Lua."""
        # Message with repeated field 1 (varint) = [1, 2, 3]
        message = bytes([
            0x08, 0x01,  # Field 1: varint 1
            0x08, 0x02,  # Field 1: varint 2
            0x08, 0x03,  # Field 1: varint 3
        ])

        fields = pb.parse_message(message)

        assert 1 in fields
        assert len(fields[1]['values']) == 3
        assert fields[1]['values'] == [1, 2, 3]


class TestWireTypeConstants:
    """Tests for wire type constant definitions in Lua."""

    @pytest.mark.req("REQ-PB-004")
    def test_wire_type_varint(self, pb: LuaBridge):
        """Verify WIRE_VARINT constant is 0."""
        assert pb.WIRE_VARINT == 0

    @pytest.mark.req("REQ-PB-004")
    def test_wire_type_64bit(self, pb: LuaBridge):
        """Verify WIRE_64BIT constant is 1."""
        assert pb.WIRE_64BIT == 1

    @pytest.mark.req("REQ-PB-004")
    def test_wire_type_length_delimited(self, pb: LuaBridge):
        """Verify WIRE_LENGTH_DELIMITED constant is 2."""
        assert pb.WIRE_LENGTH_DELIMITED == 2

    @pytest.mark.req("REQ-PB-004")
    def test_wire_type_32bit(self, pb: LuaBridge):
        """Verify WIRE_32BIT constant is 5."""
        assert pb.WIRE_32BIT == 5
