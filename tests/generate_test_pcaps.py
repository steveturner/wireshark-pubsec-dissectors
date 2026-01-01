#!/usr/bin/env python3
"""
Generate test PCAP files for TAK/CoT/OMNI protocol testing.

Creates synthetic pcap files using existing test fixtures for validating
the Wireshark Lua dissector plugins.
"""

import os
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, wrpcap, Raw

# Paths
SCRIPT_DIR = Path(__file__).parent
FIXTURES_DIR = SCRIPT_DIR / "fixtures"
COT_EXAMPLES = FIXTURES_DIR / "cot_examples"
OMNI_ASSETS = FIXTURES_DIR / "omni_assets"
OUTPUT_DIR = FIXTURES_DIR / "pcaps"

# Standard TAK ports
PORT_TAK_DEFAULT = 4242
PORT_TAK_SA_MCAST = 6969
PORT_TAK_STREAMING = 8087
PORT_TAK_CHAT = 17012
PORT_OMNI = 8089

# IP addresses for test packets
SRC_IP = "192.168.1.100"
DST_IP = "192.168.1.200"
MCAST_IP = "239.2.3.1"


def create_tcp_packet(payload: bytes, src_port: int, dst_port: int,
                      src_ip: str = SRC_IP, dst_ip: str = DST_IP) -> Ether:
    """Create a TCP packet with given payload."""
    return (
        Ether() /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="PA") /
        Raw(load=payload)
    )


def create_udp_packet(payload: bytes, src_port: int, dst_port: int,
                      src_ip: str = SRC_IP, dst_ip: str = DST_IP) -> Ether:
    """Create a UDP packet with given payload."""
    return (
        Ether() /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=src_port, dport=dst_port) /
        Raw(load=payload)
    )


def create_tak_stream_message(cot_type: str = "a-f-G", uid: str = "test-uid-123",
                               how: str = "m-g") -> bytes:
    """
    Create a TAK Stream protocol message (version 1).
    Format: 0xBF + varint_length + TakMessage protobuf
    """
    # Build CotEvent protobuf manually
    # Field 1 (type) - string
    type_bytes = cot_type.encode('utf-8')
    cot_event = bytes([0x0A, len(type_bytes)]) + type_bytes

    # Field 5 (uid) - string
    uid_bytes = uid.encode('utf-8')
    cot_event += bytes([0x2A, len(uid_bytes)]) + uid_bytes

    # Field 9 (how) - string
    how_bytes = how.encode('utf-8')
    cot_event += bytes([0x4A, len(how_bytes)]) + how_bytes

    # Wrap in TakMessage field 2 (CotEvent)
    tak_message = bytes([0x12, len(cot_event)]) + cot_event

    # TAK Stream format: 0xBF + length + message
    return bytes([0xBF, len(tak_message)]) + tak_message


def create_tak_mesh_message(version: int = 2, cot_type: str = "a-u-G",
                            uid: str = "mesh-test") -> bytes:
    """
    Create a TAK Mesh protocol message (version 2+).
    Format: 0xBF + version_varint + 0xBF + TakMessage protobuf
    """
    # Build CotEvent protobuf
    type_bytes = cot_type.encode('utf-8')
    cot_event = bytes([0x0A, len(type_bytes)]) + type_bytes

    uid_bytes = uid.encode('utf-8')
    cot_event += bytes([0x2A, len(uid_bytes)]) + uid_bytes

    # Wrap in TakMessage
    tak_message = bytes([0x12, len(cot_event)]) + cot_event

    # TAK Mesh format: 0xBF + version + 0xBF + message
    return bytes([0xBF, version, 0xBF]) + tak_message


def encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    result = []
    while value > 127:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def encode_protobuf_tag(field_num: int, wire_type: int = 2) -> bytes:
    """
    Encode a protobuf field tag.
    wire_type 0 = varint, 2 = length-delimited
    """
    tag = (field_num << 3) | wire_type
    return encode_varint(tag)


def create_omni_base_event(entity_id: int = 12345678,
                           event_type: str = "Track",
                           seq_num: int = 1) -> bytes:
    """
    Create an OMNI BaseEvent protobuf message.

    BaseEvent fields (from baseevent.proto):
      1: entity_id (uint64)
      2: origin (EventOrigin message)
      9: event_sequence_number (uint64)
      Oneof MessageEvent:
        12: track (TrackEvent)
        13: player (PlayerEvent)
        14: sensor (SensorEvent)
        15: shape (ShapeEvent)
        16: chat (ChatEvent)
        17: missionassignment (MissionAssignmentEvent)
        20: weather (WeatherEvent)
        22: airfield_status (AirfieldStatusEvent)
        23: personnelrecovery (PersonnelRecoveryEvent)
        25: entitymanagement (EntityManagementEvent)
        26: networkmanagement (NetworkManagementEvent)
        29: navigation_vector (NavigationVectorEvent)
        36: image (ImageEvent)
        37: alert (AlertEvent)
        42: flight_path (FlightPathEvent)
    """
    message = b""

    # Field 1 (entity_id) - uint64 varint
    # Tag = (1 << 3) | 0 = 0x08
    message += bytes([0x08]) + encode_varint(entity_id)

    # Field 9 (event_sequence_number) - uint64 varint
    # Tag = (9 << 3) | 0 = 0x48
    message += bytes([0x48]) + encode_varint(seq_num)

    # Map event type names to field numbers
    event_field_nums = {
        "Track": 12,
        "Player": 13,
        "Sensor": 14,
        "Shape": 15,
        "Chat": 16,
        "MissionAssignment": 17,
        "Weather": 20,
        "AirfieldStatus": 22,
        "PersonnelRecovery": 23,
        "EntityManagement": 25,
        "NetworkManagement": 26,
        "NavigationVector": 29,
        "Image": 36,
        "Alert": 37,
        "FlightPath": 42,
    }

    field_num = event_field_nums.get(event_type)
    if field_num is None:
        return message

    # Create event-specific content
    event_content = b""

    if event_type == "Track":
        # TrackEvent: field 2 is Geopoint
        # Create a simple geopoint with lat/lon
        geopoint = b""
        # Lat (field 1, double) - use fixed64 wire type (1)
        geopoint += bytes([0x09])  # tag (1 << 3) | 1
        geopoint += b'\x00\x00\x00\x00\x00\x80B@'  # 37.0 as little-endian double
        # Lon (field 2, double)
        geopoint += bytes([0x11])  # tag (2 << 3) | 1
        geopoint += b'\x00\x00\x00\x00\x00\x80[\xc0'  # -110.0 as little-endian double
        # Wrap geopoint in TrackEvent field 2
        event_content = encode_protobuf_tag(2) + encode_varint(len(geopoint)) + geopoint

    elif event_type == "Player":
        # PlayerEvent: field 3 is CommunicationParameters with callsign
        callsign = b"ALPHA-1"
        comm_params = bytes([0x0A, len(callsign)]) + callsign  # field 1 string
        event_content = encode_protobuf_tag(3) + encode_varint(len(comm_params)) + comm_params

    elif event_type == "Sensor":
        # SensorEvent: field 3 is status enum
        event_content = bytes([0x18, 0x01])  # field 3, varint, value 1 (OPERATIONAL)

    elif event_type == "Shape":
        # ShapeEvent: field 1 is SinglePoint oneof, field 8 is environment enum
        event_content = bytes([0x0A, 0x00])  # field 1 empty SinglePoint
        event_content += bytes([0x40, 0x03])  # field 8, varint, value 3 (AIR)

    elif event_type == "Chat":
        # ChatEvent: field 1 is message string
        msg = b"Test chat message"
        event_content = bytes([0x0A, len(msg)]) + msg

    elif event_type == "MissionAssignment":
        # MissionAssignmentEvent: field 1 is mission type enum
        event_content = bytes([0x08, 0x05])  # field 1, varint, value 5 (COMBAT_AIR_PATROL)

    elif event_type == "Weather":
        # WeatherEvent: field 1 is category
        event_content = bytes([0x08, 0x01])  # field 1, varint, value 1

    elif event_type == "AirfieldStatus":
        # AirfieldStatusEvent: field 1 is ICAO code string
        icao = b"KDEN"
        event_content = bytes([0x0A, len(icao)]) + icao

    elif event_type == "PersonnelRecovery":
        # PersonnelRecoveryEvent: field 1 is PR type enum
        event_content = bytes([0x08, 0x04])  # field 1, varint, value 4 (INITIATE)

    elif event_type == "EntityManagement":
        # EntityManagementEvent: field 1 is DropCommand oneof (empty message ok)
        event_content = bytes([0x0A, 0x00])  # field 1 empty Drop

    elif event_type == "NetworkManagement":
        # NetworkManagementEvent: field 1 is Ping oneof
        event_content = bytes([0x0A, 0x00])  # field 1 empty Ping

    elif event_type == "NavigationVector":
        # NavigationVectorEvent: field 1 is course wrapper
        # Wrapper: field 1 is double value
        course_wrapper = bytes([0x09]) + b'\x00\x00\x00\x00\x00\x80V@'  # 90.0 degrees
        event_content = encode_protobuf_tag(1) + encode_varint(len(course_wrapper)) + course_wrapper

    elif event_type == "Image":
        # ImageEvent: field 2 is location geopoint
        geopoint = bytes([0x09]) + b'\x00\x00\x00\x00\x00\x80B@'  # lat 37.0
        geopoint += bytes([0x11]) + b'\x00\x00\x00\x00\x00\x80[\xc0'  # lon -110.0
        event_content = encode_protobuf_tag(2) + encode_varint(len(geopoint)) + geopoint

    elif event_type == "Alert":
        # AlertEvent: field 1 is message, field 2 is category, field 6 is alert type
        msg = b"Test alert"
        event_content = bytes([0x0A, len(msg)]) + msg  # field 1 message
        event_content += bytes([0x10, 0x02])  # field 2 category CAT_2
        event_content += bytes([0x30, 0x09])  # field 6 type THREAT

    elif event_type == "FlightPath":
        # FlightPathEvent: field 4 is total_points wrapper
        pts_wrapper = bytes([0x08, 0x05])  # field 1 int32 value 5
        event_content = encode_protobuf_tag(4) + encode_varint(len(pts_wrapper)) + pts_wrapper

    # Append the event type with its tag
    tag = encode_protobuf_tag(field_num)
    message += tag + encode_varint(len(event_content)) + event_content

    return message


def generate_xml_cot_pcap():
    """Generate pcap with XML CoT messages."""
    packets = []
    port_counter = 50000

    # Load all COT examples
    if COT_EXAMPLES.exists():
        for cot_file in sorted(COT_EXAMPLES.glob("*.cot")):
            xml_content = cot_file.read_text(encoding='utf-8').encode('utf-8')

            # Create TCP packet on default TAK port
            pkt = create_tcp_packet(xml_content, port_counter, PORT_TAK_DEFAULT)
            packets.append(pkt)
            port_counter += 1

            # Also create UDP variant on SA multicast port
            pkt_udp = create_udp_packet(xml_content, port_counter, PORT_TAK_SA_MCAST,
                                        dst_ip=MCAST_IP)
            packets.append(pkt_udp)
            port_counter += 1

    return packets


def generate_tak_protobuf_pcap():
    """Generate pcap with TAK protobuf messages (Stream and Mesh)."""
    packets = []
    port_counter = 51000

    # Stream protocol messages (version 1)
    stream_types = [
        ("a-f-G-U-C", "ANDROID-device-1", "m-g"),  # Friendly ground unit
        ("a-f-A", "ANDROID-device-2", "h-e"),      # Friendly air
        ("a-h-G", "hostile-track-1", "m-r"),       # Hostile ground
        ("a-u-G", "unknown-1", "m-g"),             # Unknown
        ("b-m-p-s-p-loc", "marker-1", "h-g-i-g-o"), # Spot marker
    ]

    for cot_type, uid, how in stream_types:
        payload = create_tak_stream_message(cot_type, uid, how)
        pkt = create_tcp_packet(payload, port_counter, PORT_TAK_SA_MCAST)
        packets.append(pkt)
        port_counter += 1

    # Mesh protocol messages (version 2+)
    mesh_configs = [
        (2, "a-f-G-U-C-I", "mesh-infantry-1"),
        (2, "a-f-G-U-C-V", "mesh-vehicle-1"),
        (3, "a-f-A-M-F-Q", "mesh-aircraft-1"),
    ]

    for version, cot_type, uid in mesh_configs:
        payload = create_tak_mesh_message(version, cot_type, uid)
        pkt = create_udp_packet(payload, port_counter, PORT_TAK_SA_MCAST,
                                dst_ip=MCAST_IP)
        packets.append(pkt)
        port_counter += 1

    return packets


def generate_omni_pcap():
    """Generate pcap with OMNI protobuf messages for all event types."""
    packets = []
    port_counter = 52000

    # Create test packets for ALL OMNI event types
    omni_events = [
        # Track events
        (1001, "Track", 1),
        (1002, "Track", 2),
        # Player events
        (2001, "Player", 1),
        (2002, "Player", 2),
        # Sensor events
        (3001, "Sensor", 1),
        (3002, "Sensor", 2),
        # Shape events
        (4001, "Shape", 1),
        (4002, "Shape", 2),
        # Chat events
        (5001, "Chat", 1),
        (5002, "Chat", 2),
        # Mission Assignment events
        (6001, "MissionAssignment", 1),
        # Weather events
        (7001, "Weather", 1),
        # Airfield Status events
        (8001, "AirfieldStatus", 1),
        # Personnel Recovery events
        (9001, "PersonnelRecovery", 1),
        # Entity Management events
        (10001, "EntityManagement", 1),
        # Network Management events
        (11001, "NetworkManagement", 1),
        # Navigation Vector events
        (12001, "NavigationVector", 1),
        # Image events
        (13001, "Image", 1),
        # Alert events
        (14001, "Alert", 1),
        (14002, "Alert", 2),
        # Flight Path events
        (15001, "FlightPath", 1),
    ]

    for entity_id, event_type, seq_num in omni_events:
        payload = create_omni_base_event(entity_id, event_type, seq_num)

        # TCP variant
        pkt_tcp = create_tcp_packet(payload, port_counter, PORT_OMNI)
        packets.append(pkt_tcp)
        port_counter += 1

        # UDP variant
        pkt_udp = create_udp_packet(payload, port_counter, PORT_OMNI)
        packets.append(pkt_udp)
        port_counter += 1

    # Include binary test asset if available
    if OMNI_ASSETS.exists():
        for bin_file in OMNI_ASSETS.glob("*.bin"):
            payload = bin_file.read_bytes()
            pkt = create_tcp_packet(payload, port_counter, PORT_OMNI)
            packets.append(pkt)
            port_counter += 1

    return packets


def generate_mixed_pcap():
    """Generate pcap with mixed TAK/CoT/OMNI traffic."""
    packets = []

    # Combine all packet types
    packets.extend(generate_xml_cot_pcap())
    packets.extend(generate_tak_protobuf_pcap())
    packets.extend(generate_omni_pcap())

    return packets


def main():
    """Generate all test pcap files."""
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Generating test pcap files in {OUTPUT_DIR}")

    # Generate individual protocol pcaps
    pcaps = {
        "tak_xml_cot.pcap": generate_xml_cot_pcap(),
        "tak_protobuf.pcap": generate_tak_protobuf_pcap(),
        "omni_protobuf.pcap": generate_omni_pcap(),
        "tak_omni_mixed.pcap": generate_mixed_pcap(),
    }

    for filename, packets in pcaps.items():
        if packets:
            output_path = OUTPUT_DIR / filename
            wrpcap(str(output_path), packets)
            print(f"  Created {filename}: {len(packets)} packets")
        else:
            print(f"  Skipped {filename}: no packets generated")

    print("\nDone! Test pcap files created.")
    print(f"\nTo test with Wireshark:")
    print(f"  wireshark {OUTPUT_DIR / 'tak_omni_mixed.pcap'}")
    print(f"\nTo test with tshark:")
    print(f"  tshark -r {OUTPUT_DIR / 'tak_omni_mixed.pcap'} -V")


if __name__ == "__main__":
    main()
