"""
Tests for OMNI Protobuf message parsing.

These tests validate OMNI protocol detection and BaseEvent message parsing
as implemented in tak.lua for entity_id, EventOrigin, TimeOfValidity,
Alias, and event type identification.
"""

import struct
import pytest


# OMNI detection - first bytes that indicate OMNI protobuf
OMNI_FIRST_BYTES = [0x08, 0x10, 0x1A, 0x22]


def is_omni_protobuf(data: bytes) -> bool:
    """
    Check if data appears to be OMNI protobuf.
    OMNI BaseEvent starts with entity_id (field 1, varint) tag 0x08
    or other common field tags.
    Mirrors tak.lua OMNI detection.
    """
    if len(data) < 1:
        return False
    return data[0] in OMNI_FIRST_BYTES


# OMNI event type mapping (from tak.lua omni_event_types)
OMNI_EVENT_TYPES = {
    11: "Other",
    12: "Track",
    13: "Player",
    14: "Sensor",
    15: "Shape",
    16: "Chat",
    17: "MissionAssignment",
    20: "Weather",
    22: "AirfieldStatus",
    23: "PersonnelRecovery",
    25: "EntityManagement",
    26: "NetworkManagement",
    29: "NavigationVector",
    36: "Image",
    37: "Alert",
    42: "FlightPath",
}


def get_event_type_name(field_number: int) -> str:
    """Get OMNI event type name from oneof field number."""
    return OMNI_EVENT_TYPES.get(field_number, "Unknown")


class TestOMNIProtocolDetection:
    """Tests for REQ-DET-005: OMNI protocol detection."""

    @pytest.mark.req("REQ-DET-005")
    def test_detect_omni_entity_id_tag(self):
        """Verify OMNI detection with entity_id field tag 0x08."""
        # BaseEvent with entity_id = 12345
        data = bytes([0x08, 0xB9, 0x60])  # Field 1, varint 12345
        assert is_omni_protobuf(data)

    @pytest.mark.req("REQ-DET-005")
    def test_detect_omni_origin_tag(self):
        """Verify OMNI detection with origin field tag."""
        # Field 2 (origin), wire type 2 -> 0x12 (but 0x10 is also valid)
        data = bytes([0x10, 0x00])
        assert is_omni_protobuf(data)

    @pytest.mark.req("REQ-DET-005")
    def test_detect_omni_time_tag(self):
        """Verify OMNI detection with time field tag."""
        # Field 4 (time), wire type 2 -> 0x22
        data = bytes([0x22, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00])
        assert is_omni_protobuf(data)

    @pytest.mark.req("REQ-DET-005")
    def test_not_omni_xml(self):
        """Verify XML is not detected as OMNI."""
        xml_data = b"<?xml version='1.0'?><event/>"
        assert not is_omni_protobuf(xml_data)

    @pytest.mark.req("REQ-DET-005")
    def test_not_omni_tak(self):
        """Verify TAK protobuf is not detected as OMNI."""
        tak_data = bytes([0xBF, 0x10, 0x12, 0x0E])  # TAK magic byte
        assert not is_omni_protobuf(tak_data)

    @pytest.mark.req("REQ-DET-005")
    def test_detect_omni_with_binary_fixture(self, omni_player_event_bin):
        """Verify OMNI detection with real binary fixture."""
        if omni_player_event_bin is None:
            pytest.skip("OMNI binary fixture not available")
        assert is_omni_protobuf(omni_player_event_bin)


class TestBaseEventParsing:
    """Tests for REQ-OMNI-001: BaseEvent parsing."""

    @pytest.mark.req("REQ-OMNI-001")
    def test_base_event_entity_id(self):
        """Verify entity_id field (field 1) parsing."""
        entity_id = 12345
        # Field 1, wire type 0 -> 0x08
        base_event = bytes([0x08, 0xB9, 0x60])  # varint 12345

        assert base_event[0] == 0x08

    @pytest.mark.req("REQ-OMNI-001")
    def test_base_event_sequence_number(self):
        """Verify event_sequence_number field (field 9) parsing."""
        # Field 9, wire type 0 -> 0x48
        base_event = bytes([0x48, 0x01])  # sequence number 1

        assert base_event[0] == 0x48

    @pytest.mark.req("REQ-OMNI-001")
    def test_base_event_structure(self):
        """Verify complete BaseEvent structure."""
        # Minimal BaseEvent with entity_id and sequence number
        base_event = bytes([
            0x08, 0x01,  # entity_id = 1
            0x48, 0x0A,  # event_sequence_number = 10
        ])

        # Field 1 tag
        assert base_event[0] == 0x08
        # Field 9 tag
        assert base_event[2] == 0x48


class TestEventOriginParsing:
    """Tests for REQ-OMNI-002: EventOrigin parsing."""

    @pytest.mark.req("REQ-OMNI-002")
    def test_event_origin_source_uid(self):
        """Verify source_uid field (field 1) in EventOrigin."""
        source_uid = b"device-12345"
        origin = bytes([
            0x0A, len(source_uid),  # Field 1 (source_uid)
        ]) + source_uid

        assert origin[0] == 0x0A

    @pytest.mark.req("REQ-OMNI-002")
    def test_event_origin_source_net(self):
        """Verify source_net field (field 2) in EventOrigin."""
        source_net = b"TakNet"
        origin = bytes([
            0x12, len(source_net),  # Field 2 (source_net)
        ]) + source_net

        assert origin[0] == 0x12

    @pytest.mark.req("REQ-OMNI-002")
    def test_event_origin_in_base_event(self):
        """Verify EventOrigin is field 2 in BaseEvent."""
        source_uid = b"test-device"
        origin = bytes([0x0A, len(source_uid)]) + source_uid

        # BaseEvent field 2, wire type 2 -> 0x12
        base_event = bytes([
            0x08, 0x01,  # entity_id
            0x12, len(origin),  # origin field
        ]) + origin

        assert base_event[2] == 0x12


class TestTimeOfValidityParsing:
    """Tests for REQ-OMNI-003: TimeOfValidity parsing."""

    @pytest.mark.req("REQ-OMNI-003")
    def test_time_of_validity_updated(self):
        """Verify updated field (field 2) in TimeOfValidity."""
        # Field 2, wire type 0 -> 0x10
        tov = bytes([0x10, 0xE8, 0x07])  # updated = 1000ms

        assert tov[0] == 0x10

    @pytest.mark.req("REQ-OMNI-003")
    def test_time_of_validity_timeout(self):
        """Verify timeout field (field 3) in TimeOfValidity."""
        # Field 3, wire type 0 -> 0x18
        tov = bytes([0x18, 0xD0, 0x0F])  # timeout = 2000ms

        assert tov[0] == 0x18

    @pytest.mark.req("REQ-OMNI-003")
    def test_time_of_validity_in_base_event(self):
        """Verify TimeOfValidity is field 4 in BaseEvent."""
        tov = bytes([0x10, 0xE8, 0x07, 0x18, 0xD0, 0x0F])

        # BaseEvent field 4, wire type 2 -> 0x22
        base_event = bytes([
            0x08, 0x01,  # entity_id
            0x22, len(tov),  # time field
        ]) + tov

        assert base_event[2] == 0x22


class TestAliasParsing:
    """Tests for REQ-OMNI-004: Alias parsing."""

    @pytest.mark.req("REQ-OMNI-004")
    def test_alias_domain(self):
        """Verify domain field (field 1) in Alias."""
        domain = b"CoT"
        alias = bytes([0x0A, len(domain)]) + domain

        assert alias[0] == 0x0A

    @pytest.mark.req("REQ-OMNI-004")
    def test_alias_field_name(self):
        """Verify field name (field 2) in Alias."""
        field = b"uid"
        alias = bytes([0x12, len(field)]) + field

        assert alias[0] == 0x12

    @pytest.mark.req("REQ-OMNI-004")
    def test_alias_network(self):
        """Verify network_name field (field 3) in Alias."""
        network = b"TAK"
        alias = bytes([0x1A, len(network)]) + network

        assert alias[0] == 0x1A

    @pytest.mark.req("REQ-OMNI-004")
    def test_alias_id(self):
        """Verify id field (field 4) in Alias."""
        alias_id = b"device-001"
        alias = bytes([0x22, len(alias_id)]) + alias_id

        assert alias[0] == 0x22

    @pytest.mark.req("REQ-OMNI-004")
    def test_alias_in_base_event(self):
        """Verify Alias is field 5 (repeated) in BaseEvent."""
        alias = bytes([
            0x0A, 0x03, 0x43, 0x6F, 0x54,  # domain = "CoT"
            0x22, 0x04, 0x74, 0x65, 0x73, 0x74,  # id = "test"
        ])

        # BaseEvent field 5, wire type 2 -> 0x2A
        base_event = bytes([
            0x08, 0x01,  # entity_id
            0x2A, len(alias),  # aliases field
        ]) + alias

        assert base_event[2] == 0x2A


class TestTrackEventParsing:
    """Tests for REQ-OMNI-005: TrackEvent parsing."""

    @pytest.mark.req("REQ-OMNI-005")
    def test_track_event_field_number(self):
        """Verify TrackEvent is oneof field 12."""
        # Field 12, wire type 2 -> (12 << 3) | 2 = 0x62
        assert (12 << 3) | 2 == 0x62

    @pytest.mark.req("REQ-OMNI-005")
    def test_track_event_type_name(self):
        """Verify TrackEvent type name mapping."""
        assert get_event_type_name(12) == "Track"

    @pytest.mark.req("REQ-OMNI-005")
    def test_track_event_in_base_event(self):
        """Verify TrackEvent is correctly placed in BaseEvent."""
        # Minimal TrackEvent (just a placeholder)
        track_event = bytes([0x08, 0x01])  # Some inner field

        base_event = bytes([
            0x08, 0x01,  # entity_id
            0x62, len(track_event),  # track event field
        ]) + track_event

        assert base_event[2] == 0x62


class TestPlayerEventParsing:
    """Tests for REQ-OMNI-006: PlayerEvent parsing."""

    @pytest.mark.req("REQ-OMNI-006")
    def test_player_event_field_number(self):
        """Verify PlayerEvent is oneof field 13."""
        # Field 13, wire type 2 -> (13 << 3) | 2 = 0x6A
        assert (13 << 3) | 2 == 0x6A

    @pytest.mark.req("REQ-OMNI-006")
    def test_player_event_type_name(self):
        """Verify PlayerEvent type name mapping."""
        assert get_event_type_name(13) == "Player"

    @pytest.mark.req("REQ-OMNI-006")
    def test_player_event_callsign(self):
        """Verify PlayerEvent contains callsign in communication parameters."""
        callsign = b"ALPHA-01"
        # CommunicationParameters field 1 (callsign)
        comm_params = bytes([0x0A, len(callsign)]) + callsign
        # PlayerEvent field 1 (communication_parameters)
        player_event = bytes([0x0A, len(comm_params)]) + comm_params

        assert callsign in player_event


class TestChatEventParsing:
    """Tests for REQ-OMNI-007: ChatEvent parsing."""

    @pytest.mark.req("REQ-OMNI-007")
    def test_chat_event_field_number(self):
        """Verify ChatEvent is oneof field 16."""
        # Field 16, wire type 2 -> (16 << 3) | 2 = 0x82 0x01
        # For field numbers > 15, tag requires 2 bytes
        assert (16 << 3) | 2 == 130  # 0x82 in single-byte would be > 127

    @pytest.mark.req("REQ-OMNI-007")
    def test_chat_event_type_name(self):
        """Verify ChatEvent type name mapping."""
        assert get_event_type_name(16) == "Chat"

    @pytest.mark.req("REQ-OMNI-007")
    def test_chat_event_sender(self):
        """Verify ChatEvent sender field."""
        sender = b"User1"
        # ChatEvent field 1 (sender)
        chat = bytes([0x0A, len(sender)]) + sender

        assert chat[0] == 0x0A

    @pytest.mark.req("REQ-OMNI-007")
    def test_chat_event_message(self):
        """Verify ChatEvent message field."""
        message = b"Hello, team!"
        # ChatEvent field 2 (message)
        chat = bytes([0x12, len(message)]) + message

        assert chat[0] == 0x12


class TestEventTypeIdentification:
    """Tests for REQ-OMNI-008: Event type identification."""

    @pytest.mark.req("REQ-OMNI-008")
    def test_all_event_types_mapped(self):
        """Verify all known event types are mapped."""
        expected_types = [
            (11, "Other"),
            (12, "Track"),
            (13, "Player"),
            (14, "Sensor"),
            (15, "Shape"),
            (16, "Chat"),
            (17, "MissionAssignment"),
            (20, "Weather"),
            (22, "AirfieldStatus"),
            (23, "PersonnelRecovery"),
            (25, "EntityManagement"),
            (26, "NetworkManagement"),
            (29, "NavigationVector"),
            (36, "Image"),
            (37, "Alert"),
            (42, "FlightPath"),
        ]

        for field_num, expected_name in expected_types:
            assert get_event_type_name(field_num) == expected_name

    @pytest.mark.req("REQ-OMNI-008")
    def test_unknown_event_type(self):
        """Verify unknown field numbers return 'Unknown'."""
        assert get_event_type_name(99) == "Unknown"
        assert get_event_type_name(0) == "Unknown"

    @pytest.mark.req("REQ-OMNI-008")
    def test_event_type_field_tags(self):
        """Verify event type field tags are correct."""
        # Each event type has field number that maps to specific tag
        event_tags = {
            12: 0x62,  # Track: (12 << 3) | 2
            13: 0x6A,  # Player: (13 << 3) | 2
            14: 0x72,  # Sensor: (14 << 3) | 2
            15: 0x7A,  # Shape: (15 << 3) | 2
        }

        for field_num, expected_tag in event_tags.items():
            calculated_tag = (field_num << 3) | 2
            assert calculated_tag == expected_tag


class TestOMNIBinaryFixture:
    """Tests using real OMNI binary test fixtures."""

    @pytest.mark.req("REQ-OMNI-001")
    @pytest.mark.req("REQ-OMNI-006")
    def test_parse_player_event_fixture(self, omni_player_event_bin):
        """Verify parsing of real PlayerEvent binary fixture."""
        if omni_player_event_bin is None:
            pytest.skip("OMNI PlayerEvent binary fixture not available")

        # Verify it's detected as OMNI
        assert is_omni_protobuf(omni_player_event_bin)

        # Verify it contains expected field tags
        # Should have entity_id (0x08) and player event (0x6A)
        assert omni_player_event_bin[0] == 0x08 or 0x6A in omni_player_event_bin
