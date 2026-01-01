# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Wireshark Lua plugin for dissecting TAK (Team Awareness Kit), CoT (Cursor-on-Target), and OMNI (Open Mission Network Interface) protocol messages. The plugin includes native protobuf parsing - no external dependencies required.

## Supported Protocols

### TAK Protobuf (port 6969)
- **XML CoT** (version 0): Plain XML messages starting with `<?xml` or `<event`
- **Stream protocol** (version 1): `0xBF` magic byte + varint length + TakMessage protobuf
- **Mesh protocol** (version 2+): `0xBF` + version varint + `0xBF` + TakMessage protobuf

### OMNI Protobuf (port 8089)
- Open Mission Network Interface
- BaseEvent messages with various event types (Track, Player, Chat, Sensor, Shape, Weather, etc.)

## Architecture

The plugin is split into two files for protocol separation:
- **`tak.lua`** (~890 lines): TAK Protobuf and CoT XML protocols
- **`omni.lua`** (~380 lines): OMNI Protobuf protocol

Both files include a native protobuf decoder for installation simplicity (no shared dependencies).

### tak.lua - TAK/CoT Protocol

#### Native Protobuf Decoder
The `pb` module implements protobuf parsing without external dependencies:
- `pb.decode_varint()` - Decode variable-length integers
- `pb.decode_tag()` - Parse field number and wire type
- `pb.parse_message()` - Extract all fields from a protobuf message
- Helper functions: `pb.get_string()`, `pb.get_field()`, `pb.get_uint64()`

#### XML Parser
Simple regex-based XML attribute/element extraction for CoT XML messages.

#### Protocol Fields
Wireshark ProtoField definitions for TAK dissected values:
- Common fields (protocol, version, length)
- TAK Control fields (min/max proto version)
- CoT Event fields (type, uid, how, timestamps)
- Point fields (lat, lon, hae, ce, le)
- Detail sub-fields (contact, group, status, takv, track, precisionlocation)

#### Message Parsers
- **TAK Protobuf**: Parses TakMessage → TakControl + CotEvent → Detail sub-messages
- **XML CoT**: Extracts event, point, and detail attributes from XML

#### Main Dissector
Entry point that detects message format and routes to appropriate parser:
1. Check for XML (`<?xml` or `<event` prefix)
2. Check for TAK magic byte (`0xBF`) → Stream or Mesh protocol
3. Mark as unsupported if unrecognized

### omni.lua - OMNI Protocol

#### Protocol Fields
Wireshark ProtoField definitions for OMNI dissected values:
- BaseEvent fields (entity_id, sequence_number)
- EventOrigin fields (source_uid, source_net)
- TimeOfValidity fields (updated, timeout)
- Alias fields (domain, name, network, id)
- Event type field for oneof events (Track, Player, Chat, etc.)

#### Message Parsers
- **BaseEvent Parser**: Parses top-level OMNI message
- **Event-specific Parsers**: Track, Player, Chat, and other event types

## Reference Materials

The repository includes protocol definitions in subdirectories (not part of the plugin):
- `takproto-master/` - TAK protobuf definitions (TakMessage, CotEvent, Detail, etc.)
- `omni-master/protos/` - OMNI protobuf definitions (BaseEvent, TrackEvent, etc.)
- `takcot-master/xsd/` - CoT XML schema definitions

## Installation

**Automatic:**
```bash
./install.sh                # macOS/Linux
powershell -File install.ps1  # Windows
```

**Manual:** Copy `tak.lua` and `omni.lua` to Wireshark plugins directory and reload

## Configuration

**TAK Protocol** (Edit → Preferences → Protocols → TAK):
- **TAK Port**: TCP/UDP port for TAK messages (default: 6969)

**OMNI Protocol** (Edit → Preferences → Protocols → OMNI):
- **OMNI Port**: TCP/UDP port for OMNI messages (default: 8089)

## Display Filters

### TAK/CoT Filters
```
tak                          # All TAK traffic
tak.protocol == "xml"        # XML CoT messages
tak.protocol == "mesh"       # Mesh protocol messages
tak.protocol == "stream"     # Stream protocol messages
tak.cot.type                 # Filter by CoT event type
tak.cot.uid contains "ANDROID"  # Filter by UID pattern
tak.point.lat > 38.0         # Filter by latitude
tak.detail.contact.callsign  # Filter by callsign
```

### OMNI Filters
```
omni                         # All OMNI traffic
omni.entity_id               # Filter by entity ID
omni.event_type == "Track"   # Track events
omni.event_type == "Player"  # Player events
omni.event_type == "Chat"    # Chat events
```


## RTMX

This project uses RTMX for requirements traceability.

### Quick Commands
- `rtmx status` - Show RTM progress
- `rtmx backlog` - View prioritized backlog
- `rtmx health` - Run health checks

### When Implementing Requirements
1. Check the RTM: `rtmx status`
2. Mark tests with `@pytest.mark.req("REQ-XXX-NNN")`
3. Update status when complete

### RTM Location
- Database: `docs/rtm_database.csv`
- Specs: `docs/requirements/`
