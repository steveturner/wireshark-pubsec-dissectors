"""
Lua Bridge for Testing tak.lua and omni.lua

This module provides a Python interface to the actual Lua code in tak.lua
and omni.lua, allowing tests to exercise the real implementation rather
than Python reimplementations.
"""

import struct
from pathlib import Path
from typing import Any

import lupa
from lupa import LuaRuntime


class LuaBridge:
    """Bridge to execute tak.lua code from Python tests."""

    def __init__(self):
        """Initialize Lua runtime and load tak.lua with mocks."""
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self._load_mocks()
        self._load_tak_plugin()

    def _load_mocks(self):
        """Load Wireshark API mocks."""
        mock_path = Path(__file__).parent / "wireshark_mock.lua"
        with open(mock_path, "r") as f:
            mock_code = f.read()
        self.lua.execute(mock_code)

    def _load_tak_plugin(self):
        """Load tak.lua plugin code."""
        plugin_path = Path(__file__).parent.parent / "tak.lua"
        with open(plugin_path, "r") as f:
            plugin_code = f.read()

        # Modify the code to export the pb and xml modules to globals
        # This allows us to access them after execution
        modified_code = plugin_code + """

-- Export modules for testing
_G._test_pb = pb
_G._test_xml = xml
"""
        self.lua.execute(modified_code)

        # Get references to the Lua modules via the globals we created
        self._pb = self.lua.eval("_test_pb")
        self._xml = self.lua.eval("_test_xml")
        self._tvb_class = self.lua.eval("Tvb")

    def create_buffer(self, data: bytes | list[int]) -> Any:
        """Create a Lua Tvb buffer from Python bytes or byte list."""
        if isinstance(data, bytes):
            data = list(data)
        # Create Lua table from Python list
        lua_table = self.lua.table(*data)
        return self._tvb_class.new(lua_table)

    # =========================================================================
    # Protobuf Decoder Functions
    # =========================================================================

    def decode_varint(self, data: bytes, offset: int = 0) -> tuple[int | None, int]:
        """Decode a varint from buffer at offset."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_varint(buffer, offset)
        if result is None:
            return None, 0
        # lupa returns tuple when unpack_returned_tuples=True
        if isinstance(result, tuple):
            return result
        return result, 0

    def decode_sint(self, data: bytes, offset: int = 0) -> tuple[int | None, int]:
        """Decode a signed varint (zigzag encoding)."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_sint(buffer, offset)
        if result is None:
            return None, 0
        if isinstance(result, tuple):
            return result
        return result, 0

    def decode_fixed32(self, data: bytes, offset: int = 0) -> tuple[int | None, int]:
        """Decode a 32-bit fixed value."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_fixed32(buffer, offset)
        if result is None:
            return None, 0
        if isinstance(result, tuple):
            return result
        return result, 0

    def decode_fixed64(self, data: bytes, offset: int = 0) -> tuple[int | None, int]:
        """Decode a 64-bit fixed value."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_fixed64(buffer, offset)
        if result is None:
            return None, 0
        if isinstance(result, tuple):
            return result
        return result, 0

    def decode_float(self, data: bytes, offset: int = 0) -> tuple[float | None, int]:
        """Decode a 32-bit float."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_float(buffer, offset)
        if result is None:
            return None, 0
        if isinstance(result, tuple):
            return result
        return result, 0

    def decode_double(self, data: bytes, offset: int = 0) -> tuple[float | None, int]:
        """Decode a 64-bit double."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_double(buffer, offset)
        if result is None:
            return None, 0
        if isinstance(result, tuple):
            return result
        return result, 0

    def decode_tag(self, data: bytes, offset: int = 0) -> tuple[int | None, int | None, int]:
        """Decode a protobuf field tag."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_tag(buffer, offset)
        if result is None:
            return None, None, 0
        if isinstance(result, tuple) and len(result) == 3:
            return result
        return None, None, 0

    def decode_length_delimited(
        self, data: bytes, offset: int = 0
    ) -> tuple[bytes | None, int | None, int]:
        """Decode a length-delimited field."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_length_delimited(buffer, offset)
        if result is None:
            return None, None, 0
        if isinstance(result, tuple) and len(result) == 3:
            lua_data, length, total_bytes = result
            if lua_data is not None:
                # Convert TvbRange to bytes - need to call Lua method correctly
                try:
                    # lua_data is a TvbRange, call its string method
                    str_result = lua_data.string(lua_data)  # Pass self explicitly
                    if isinstance(str_result, str):
                        return str_result.encode(), length, total_bytes
                    elif isinstance(str_result, bytes):
                        return str_result, length, total_bytes
                    return str_result, length, total_bytes
                except Exception:
                    return None, length, total_bytes
            return None, length, total_bytes
        return None, None, 0

    def parse_message(self, data: bytes, offset: int = 0, length: int | None = None) -> dict:
        """Parse all fields from a protobuf message."""
        if length is None:
            length = len(data) - offset
        buffer = self.create_buffer(data)
        lua_fields = self._pb.parse_message(buffer, offset, length)

        # Convert Lua table to Python dict
        result = {}
        if lua_fields:
            # Iterate over Lua table using lupa's iteration
            for field_num, field_data in lua_fields.items():
                if field_num is not None and field_data is not None:
                    # Access wire_type from the Lua table
                    wire_type = field_data["wire_type"]
                    values = []

                    # Access values array from the Lua table
                    lua_values = field_data["values"]
                    if lua_values:
                        # Iterate using lupa's values() for array-like tables
                        for v in lua_values.values():
                            if v is None:
                                break
                            # Convert TvbRange to string if needed
                            if hasattr(v, 'string'):
                                try:
                                    values.append(v.string(v))  # Pass self explicitly
                                except Exception:
                                    values.append(v)
                            else:
                                values.append(v)

                    result[int(field_num)] = {'wire_type': int(wire_type), 'values': values}
        return result

    # =========================================================================
    # Wire Type Constants
    # =========================================================================

    @property
    def WIRE_VARINT(self) -> int:
        return int(self._pb.WIRE_VARINT)

    @property
    def WIRE_64BIT(self) -> int:
        return int(self._pb.WIRE_64BIT)

    @property
    def WIRE_LENGTH_DELIMITED(self) -> int:
        return int(self._pb.WIRE_LENGTH_DELIMITED)

    @property
    def WIRE_32BIT(self) -> int:
        return int(self._pb.WIRE_32BIT)

    # =========================================================================
    # XML Parser Functions
    # =========================================================================

    def xml_get_attr(self, xml_str: str, attr_name: str) -> str | None:
        """Extract attribute value from XML string."""
        result = self._xml.get_attr(xml_str, attr_name)
        return result if result else None

    def xml_get_element(self, xml_str: str, elem_name: str) -> str | None:
        """Extract element content from XML string."""
        result = self._xml.get_element(xml_str, elem_name)
        return result if result else None

    def xml_get_element_with_attrs(self, xml_str: str, elem_name: str) -> str | None:
        """Extract element with attributes from XML string."""
        result = self._xml.get_element_with_attrs(xml_str, elem_name)
        return result if result else None

    def xml_is_xml(self, data: str) -> bool:
        """Check if string appears to be XML."""
        return bool(self._xml.is_xml(data))


class OmniBridge:
    """Bridge to execute omni.lua code from Python tests."""

    def __init__(self):
        """Initialize Lua runtime and load omni.lua with mocks."""
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self._load_mocks()
        self._load_omni_plugin()

    def _load_mocks(self):
        """Load Wireshark API mocks."""
        mock_path = Path(__file__).parent / "wireshark_mock.lua"
        with open(mock_path, "r") as f:
            mock_code = f.read()
        self.lua.execute(mock_code)

    def _load_omni_plugin(self):
        """Load omni.lua plugin code."""
        plugin_path = Path(__file__).parent.parent / "omni.lua"
        with open(plugin_path, "r") as f:
            plugin_code = f.read()

        # Modify the code to export the pb module to globals
        modified_code = plugin_code + """

-- Export modules for testing
_G._test_pb = pb
"""
        self.lua.execute(modified_code)

        # Get references to the Lua modules
        self._pb = self.lua.eval("_test_pb")
        self._tvb_class = self.lua.eval("Tvb")

    def create_buffer(self, data: bytes | list[int]) -> Any:
        """Create a Lua Tvb buffer from Python bytes or byte list."""
        if isinstance(data, bytes):
            data = list(data)
        lua_table = self.lua.table(*data)
        return self._tvb_class.new(lua_table)

    # =========================================================================
    # Protobuf Decoder Functions
    # =========================================================================

    def decode_varint(self, data: bytes, offset: int = 0) -> tuple[int | None, int]:
        """Decode a varint from buffer at offset."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_varint(buffer, offset)
        if result is None:
            return None, 0
        if isinstance(result, tuple):
            return result
        return result, 0

    def decode_tag(self, data: bytes, offset: int = 0) -> tuple[int | None, int | None, int]:
        """Decode a protobuf field tag."""
        buffer = self.create_buffer(data)
        result = self._pb.decode_tag(buffer, offset)
        if result is None:
            return None, None, 0
        if isinstance(result, tuple) and len(result) == 3:
            return result
        return None, None, 0

    def parse_message(self, data: bytes, offset: int = 0, length: int | None = None) -> dict:
        """Parse all fields from a protobuf message."""
        if length is None:
            length = len(data) - offset
        buffer = self.create_buffer(data)
        lua_fields = self._pb.parse_message(buffer, offset, length)

        result = {}
        if lua_fields:
            for field_num, field_data in lua_fields.items():
                if field_num is not None and field_data is not None:
                    wire_type = field_data["wire_type"]
                    values = []
                    lua_values = field_data["values"]
                    if lua_values:
                        for v in lua_values.values():
                            if v is None:
                                break
                            if hasattr(v, 'string'):
                                try:
                                    values.append(v.string(v))
                                except Exception:
                                    values.append(v)
                            else:
                                values.append(v)
                    result[int(field_num)] = {'wire_type': int(wire_type), 'values': values}
        return result

    @property
    def WIRE_VARINT(self) -> int:
        return int(self._pb.WIRE_VARINT)

    @property
    def WIRE_64BIT(self) -> int:
        return int(self._pb.WIRE_64BIT)

    @property
    def WIRE_LENGTH_DELIMITED(self) -> int:
        return int(self._pb.WIRE_LENGTH_DELIMITED)

    @property
    def WIRE_32BIT(self) -> int:
        return int(self._pb.WIRE_32BIT)


# Singleton instances
_bridge: LuaBridge | None = None
_omni_bridge: OmniBridge | None = None


def get_bridge() -> LuaBridge:
    """Get or create the Lua bridge singleton."""
    global _bridge
    if _bridge is None:
        _bridge = LuaBridge()
    return _bridge


def get_omni_bridge() -> OmniBridge:
    """Get or create the OMNI Lua bridge singleton."""
    global _omni_bridge
    if _omni_bridge is None:
        _omni_bridge = OmniBridge()
    return _omni_bridge


def reset_bridge():
    """Reset the Lua bridge (useful for test isolation)."""
    global _bridge, _omni_bridge
    _bridge = None
    _omni_bridge = None
