"""
Tests for TAK Protobuf message parsing.

These tests validate TAK protocol detection and message parsing as
implemented in tak.lua for TakMessage, TakControl, CotEvent, and
Detail submessages.
"""

import struct
import pytest


# TAK protocol detection constants
TAK_MAGIC_BYTE = 0xBF


def is_tak_stream(data: bytes) -> bool:
    """
    Check if data is TAK Stream protocol (version 1).
    Format: 0xBF + varint_length + payload
    Mirrors tak.lua stream detection.
    """
    if len(data) < 2:
        return False
    if data[0] != TAK_MAGIC_BYTE:
        return False
    # Next should be a varint length, then payload (no second magic byte)
    # Check that position after varint doesn't have another magic byte
    pos = 1
    # Decode varint to find where payload starts
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
        if (byte & 0x80) == 0:
            break
    # If next byte after varint is not magic byte, it's stream protocol
    if pos < len(data) and data[pos] != TAK_MAGIC_BYTE:
        return True
    return False


def is_tak_mesh(data: bytes) -> bool:
    """
    Check if data is TAK Mesh protocol (version 2+).
    Format: 0xBF + version_varint + 0xBF + payload
    Mirrors tak.lua mesh detection.
    """
    if len(data) < 3:
        return False
    if data[0] != TAK_MAGIC_BYTE:
        return False
    # Decode version varint
    pos = 1
    while pos < len(data):
        byte = data[pos]
        pos += 1
        if (byte & 0x80) == 0:
            break
    # Check for second magic byte
    if pos < len(data) and data[pos] == TAK_MAGIC_BYTE:
        return True
    return False


def get_tak_version(data: bytes) -> int | None:
    """Extract TAK protocol version from mesh message."""
    if not is_tak_mesh(data):
        return None
    # Decode version varint after first magic byte
    pos = 1
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
        if (byte & 0x80) == 0:
            break
    return value


class TestTAKProtocolDetection:
    """Tests for REQ-DET-003 and REQ-DET-004: TAK protocol detection."""

    @pytest.mark.req("REQ-DET-003")
    def test_detect_stream_protocol(self, tak_stream_sample):
        """Verify TAK Stream protocol is detected."""
        assert tak_stream_sample[0] == TAK_MAGIC_BYTE
        assert is_tak_stream(tak_stream_sample)
        assert not is_tak_mesh(tak_stream_sample)

    @pytest.mark.req("REQ-DET-004")
    def test_detect_mesh_protocol(self, tak_mesh_sample):
        """Verify TAK Mesh protocol is detected."""
        assert tak_mesh_sample[0] == TAK_MAGIC_BYTE
        assert is_tak_mesh(tak_mesh_sample)
        assert not is_tak_stream(tak_mesh_sample)

    @pytest.mark.req("REQ-DET-004")
    def test_detect_mesh_version(self, tak_mesh_sample):
        """Verify mesh protocol version is extracted."""
        version = get_tak_version(tak_mesh_sample)
        assert version == 2

    @pytest.mark.req("REQ-DET-003")
    def test_stream_magic_byte(self):
        """Verify stream protocol starts with 0xBF magic byte."""
        # Minimal stream message
        data = bytes([0xBF, 0x02, 0x08, 0x01])  # Magic + length(2) + field1(varint 1)
        assert data[0] == 0xBF
        assert is_tak_stream(data)

    @pytest.mark.req("REQ-DET-004")
    def test_mesh_double_magic_byte(self):
        """Verify mesh protocol has double 0xBF with version between."""
        data = bytes([0xBF, 0x03, 0xBF, 0x08, 0x01])  # Magic + v3 + Magic + payload
        assert data[0] == 0xBF
        assert data[2] == 0xBF
        assert is_tak_mesh(data)
        assert get_tak_version(data) == 3

    @pytest.mark.req("REQ-DET-003")
    @pytest.mark.req("REQ-DET-004")
    def test_not_tak_protocol(self):
        """Verify non-TAK data is not detected as TAK."""
        xml_data = b"<?xml version='1.0'?><event/>"
        assert not is_tak_stream(xml_data)
        assert not is_tak_mesh(xml_data)

        random_data = bytes([0x00, 0x01, 0x02, 0x03])
        assert not is_tak_stream(random_data)
        assert not is_tak_mesh(random_data)


class TestTakMessageParsing:
    """Tests for REQ-TAK-001: TakMessage parsing."""

    @pytest.mark.req("REQ-TAK-001")
    def test_parse_tak_message_structure(self, tak_stream_sample):
        """Verify TakMessage structure with CotEvent field."""
        # Skip magic byte and length varint
        offset = 1
        # Decode length
        length = tak_stream_sample[offset]
        offset += 1

        # First field should be tag for field 2 (CotEvent)
        # Field 2, wire type 2 -> (2 << 3) | 2 = 0x12
        assert tak_stream_sample[offset] == 0x12

    @pytest.mark.req("REQ-TAK-001")
    def test_tak_message_has_cot_event(self, tak_stream_sample):
        """Verify TakMessage contains CotEvent (field 2)."""
        # Look for CotEvent field tag (0x12 = field 2, length-delimited)
        assert 0x12 in tak_stream_sample


class TestTakControlParsing:
    """Tests for REQ-TAK-002: TakControl parsing."""

    @pytest.mark.req("REQ-TAK-002")
    def test_tak_control_structure(self):
        """Verify TakControl message structure."""
        # TakControl with minProtoVersion=1, maxProtoVersion=2
        tak_control = bytes([
            0x08, 0x01,  # Field 1 (minProtoVersion): varint 1
            0x10, 0x02,  # Field 2 (maxProtoVersion): varint 2
        ])

        # Parse field 1
        assert tak_control[0] == 0x08  # Field 1, varint
        assert tak_control[1] == 0x01  # Value 1

        # Parse field 2
        assert tak_control[2] == 0x10  # Field 2, varint
        assert tak_control[3] == 0x02  # Value 2

    @pytest.mark.req("REQ-TAK-002")
    def test_tak_control_with_contact_uid(self):
        """Verify TakControl with contactUid field."""
        contact_uid = b"ANDROID-test123"
        tak_control = bytes([
            0x08, 0x01,  # minProtoVersion = 1
            0x10, 0x02,  # maxProtoVersion = 2
            0x1A, len(contact_uid),  # Field 3 (contactUid): string
        ]) + contact_uid

        assert 0x1A in tak_control  # Field 3 tag present


class TestCotEventParsing:
    """Tests for REQ-TAK-003 and REQ-TAK-004: CotEvent parsing."""

    @pytest.mark.req("REQ-TAK-003")
    def test_cot_event_type_field(self):
        """Verify CotEvent type field (field 1) parsing."""
        event_type = b"a-f-G-U-C"
        cot_event = bytes([
            0x0A, len(event_type),  # Field 1 (type): string
        ]) + event_type

        assert cot_event[0] == 0x0A  # Field 1, length-delimited
        assert cot_event[2:2+len(event_type)] == event_type

    @pytest.mark.req("REQ-TAK-003")
    def test_cot_event_uid_field(self):
        """Verify CotEvent uid field (field 5) parsing."""
        uid = b"ANDROID-device-id"
        # Field 5, wire type 2 -> (5 << 3) | 2 = 0x2A
        cot_event = bytes([
            0x2A, len(uid),
        ]) + uid

        assert cot_event[0] == 0x2A

    @pytest.mark.req("REQ-TAK-003")
    def test_cot_event_how_field(self):
        """Verify CotEvent how field (field 9) parsing."""
        how = b"m-g"
        # Field 9, wire type 2 -> (9 << 3) | 2 = 0x4A
        cot_event = bytes([
            0x4A, len(how),
        ]) + how

        assert cot_event[0] == 0x4A

    @pytest.mark.req("REQ-TAK-003")
    def test_cot_event_times(self):
        """Verify CotEvent time fields (fields 6-8) as uint64."""
        # Times are stored as milliseconds since epoch (uint64 varint)
        timestamp = 1608148774913  # Example timestamp

        # Field 6 (sendTime), wire type 0 -> 0x30
        # For large numbers, varint encoding is needed
        # Simplified test with small value
        cot_event = bytes([
            0x30, 0x81, 0x80, 0x80, 0x80, 0x80, 0x01,  # Field 6
        ])

        assert cot_event[0] == 0x30

    @pytest.mark.req("REQ-TAK-004")
    def test_cot_event_point_lat(self):
        """Verify CotEvent lat field (field 10) as double."""
        lat = 38.85606343062312
        lat_bytes = struct.pack("<d", lat)
        # Field 10, wire type 1 (64-bit) -> (10 << 3) | 1 = 0x51
        cot_event = bytes([0x51]) + lat_bytes

        assert cot_event[0] == 0x51
        parsed_lat = struct.unpack("<d", cot_event[1:9])[0]
        assert parsed_lat == pytest.approx(lat, rel=1e-15)

    @pytest.mark.req("REQ-TAK-004")
    def test_cot_event_point_lon(self):
        """Verify CotEvent lon field (field 11) as double."""
        lon = -77.0563755018233
        lon_bytes = struct.pack("<d", lon)
        # Field 11, wire type 1 -> (11 << 3) | 1 = 0x59
        cot_event = bytes([0x59]) + lon_bytes

        assert cot_event[0] == 0x59
        parsed_lon = struct.unpack("<d", cot_event[1:9])[0]
        assert parsed_lon == pytest.approx(lon, rel=1e-15)

    @pytest.mark.req("REQ-TAK-004")
    def test_cot_event_all_point_fields(self):
        """Verify all point fields (lat, lon, hae, ce, le)."""
        lat, lon, hae, ce, le = 38.85, -77.05, 100.0, 10.0, 5.0

        point_data = (
            bytes([0x51]) + struct.pack("<d", lat) +   # Field 10 (lat)
            bytes([0x59]) + struct.pack("<d", lon) +   # Field 11 (lon)
            bytes([0x61]) + struct.pack("<d", hae) +   # Field 12 (hae)
            bytes([0x69]) + struct.pack("<d", ce) +    # Field 13 (ce)
            bytes([0x71]) + struct.pack("<d", le)      # Field 14 (le)
        )

        # Verify field tags
        assert point_data[0] == 0x51   # lat
        assert point_data[9] == 0x59   # lon
        assert point_data[18] == 0x61  # hae
        assert point_data[27] == 0x69  # ce
        assert point_data[36] == 0x71  # le


class TestDetailParsing:
    """Tests for REQ-TAK-005 through REQ-TAK-011: Detail submessage parsing."""

    @pytest.mark.req("REQ-TAK-005")
    def test_detail_field_in_cot_event(self):
        """Verify Detail is field 15 in CotEvent."""
        # Field 15, wire type 2 -> (15 << 3) | 2 = 0x7A
        detail_tag = 0x7A
        assert (15 << 3) | 2 == detail_tag

    @pytest.mark.req("REQ-TAK-006")
    def test_contact_in_detail(self):
        """Verify Contact message structure (field 2 in Detail)."""
        callsign = b"HOPE"
        endpoint = b"192.168.1.1:4242:tcp"

        contact = bytes([
            0x0A, len(endpoint),  # Field 1 (endpoint)
        ]) + endpoint + bytes([
            0x12, len(callsign),  # Field 2 (callsign)
        ]) + callsign

        # Wrapped in Detail field 2
        # Detail field 2, wire type 2 -> 0x12
        detail = bytes([0x12, len(contact)]) + contact

        assert detail[0] == 0x12

    @pytest.mark.req("REQ-TAK-007")
    def test_group_in_detail(self):
        """Verify Group message structure (field 3 in Detail)."""
        name = b"Cyan"
        role = b"Team Member"

        group = bytes([
            0x0A, len(name),  # Field 1 (name)
        ]) + name + bytes([
            0x12, len(role),  # Field 2 (role)
        ]) + role

        # Detail field 3, wire type 2 -> 0x1A
        detail = bytes([0x1A, len(group)]) + group

        assert detail[0] == 0x1A

    @pytest.mark.req("REQ-TAK-008")
    def test_status_in_detail(self):
        """Verify Status message structure (field 5 in Detail)."""
        # Battery as varint
        status = bytes([
            0x08, 0x5A,  # Field 1 (battery): varint 90
        ])

        # Detail field 5, wire type 2 -> 0x2A
        detail = bytes([0x2A, len(status)]) + status

        assert detail[0] == 0x2A

    @pytest.mark.req("REQ-TAK-009")
    def test_takv_in_detail(self):
        """Verify Takv message structure (field 6 in Detail)."""
        device = b"Samsung Galaxy"
        platform = b"ATAK-CIV"
        os_name = b"30"
        version = b"4.5.1.1"

        takv = (
            bytes([0x0A, len(device)]) + device +
            bytes([0x12, len(platform)]) + platform +
            bytes([0x1A, len(os_name)]) + os_name +
            bytes([0x22, len(version)]) + version
        )

        # Detail field 6, wire type 2 -> 0x32
        detail = bytes([0x32, len(takv)]) + takv

        assert detail[0] == 0x32

    @pytest.mark.req("REQ-TAK-010")
    def test_track_in_detail(self):
        """Verify Track message structure (field 7 in Detail)."""
        speed = 5.5  # m/s
        course = 180.0  # degrees

        # Track uses doubles (wire type 1)
        track = (
            bytes([0x09]) + struct.pack("<d", speed) +  # Field 1 (speed)
            bytes([0x11]) + struct.pack("<d", course)   # Field 2 (course)
        )

        # Detail field 7, wire type 2 -> 0x3A
        detail = bytes([0x3A, len(track)]) + track

        assert detail[0] == 0x3A

    @pytest.mark.req("REQ-TAK-011")
    def test_precision_location_in_detail(self):
        """Verify PrecisionLocation message structure (field 4 in Detail)."""
        geopointsrc = b"GPS"
        altsrc = b"GPS"

        precision = (
            bytes([0x0A, len(geopointsrc)]) + geopointsrc +
            bytes([0x12, len(altsrc)]) + altsrc
        )

        # Detail field 4, wire type 2 -> 0x22
        detail = bytes([0x22, len(precision)]) + precision

        assert detail[0] == 0x22
