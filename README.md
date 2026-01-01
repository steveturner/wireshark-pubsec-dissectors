# Wireshark TAK Plugin

Dissect TAK, Cursor-on-Target, and OMNI protocol messages in Wireshark.

## Supported Protocols

| Protocol | Description |
|----------|-------------|
| TAK XML CoT | Plain XML Cursor-on-Target messages |
| TAK Stream | Binary protobuf (version 1) |
| TAK Mesh | Binary protobuf (version 2+) |
| OMNI | Open Mission Network Interface |

All protobuf parsing is native Lua - no external dependencies.

## Installation

```bash
./install.sh                # macOS/Linux
powershell -File install.ps1  # Windows
```

Or manually copy `tak.lua` and `omni.lua` to your [Wireshark plugins directory](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

## Default Ports

| Port | Protocol |
|------|----------|
| 4242, 6969, 7171, 8087, 17012 | TAK |
| 8089 | OMNI |

Configure via Edit → Preferences → Protocols → TAK/OMNI.

## Display Filters

```
tak                           # All TAK/OMNI traffic
tak.protocol == "mesh"        # Mesh protocol
tak.cot.type contains "a-f"   # Friendly units
tak.point.lat > 38.0          # Filter by latitude
omni.event_type == "Track"    # OMNI track events
```

## TLS Decryption

TAK traffic is often TLS-encrypted. See [Wireshark's TLS documentation](https://wiki.wireshark.org/TLS) for decryption methods.

## Contributing

1. Fork and clone
2. Create feature branch
3. Submit PR against `main`
