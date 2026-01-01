-- TAK Protocol Plugin
-- Supports: TAK Protobuf and CoT XML protocols
-- No external dependencies required - native protobuf parsing included

-- Metadata
set_plugin_info({
    description = "Wireshark plugin for TAK/CoT protocols.",
    author      = "Joshua M. Keyes <joshua.michael.keyes@gmail.com>",
    repository  = "https://github.com/jmkeyes/wireshark-tak-plugin",
    version     = "2.0.0",
})

--------------------------------------------------------------------------------
-- Protobuf Decoder (Native Lua Implementation)
--------------------------------------------------------------------------------

local pb = {}

-- Wire types
pb.WIRE_VARINT = 0
pb.WIRE_64BIT = 1
pb.WIRE_LENGTH_DELIMITED = 2
pb.WIRE_32BIT = 5

-- Decode a varint from buffer at offset, returns value and bytes consumed
-- Uses UInt64 for values > 32 bits to handle timestamps properly
function pb.decode_varint(buffer, offset)
    local bytes_read = 0
    local bytes = {}

    -- Collect all bytes of the varint
    while true do
        if offset + bytes_read >= buffer:len() then
            return nil, 0
        end

        local byte = buffer:range(offset + bytes_read, 1):uint()
        bytes_read = bytes_read + 1
        table.insert(bytes, byte)

        if bit.band(byte, 0x80) == 0 then
            break
        end

        if bytes_read > 10 then
            return nil, 0
        end
    end

    -- For small varints (up to 4 bytes / 28 bits), use regular Lua numbers
    if bytes_read <= 4 then
        local value = 0
        local shift = 0
        for _, byte in ipairs(bytes) do
            value = value + bit.lshift(bit.band(byte, 0x7f), shift)
            shift = shift + 7
        end
        return value, bytes_read
    end

    -- For larger varints, use UInt64 to handle 64-bit timestamps
    local lo = UInt64(0)
    local hi = UInt64(0)
    local shift = 0

    for _, byte in ipairs(bytes) do
        local bits = UInt64(bit.band(byte, 0x7f))
        if shift < 32 then
            lo = lo + bits:lshift(shift)
            -- Handle overflow from low to high
            if shift > 25 then
                hi = hi + bits:rshift(32 - shift)
            end
        else
            hi = hi + bits:lshift(shift - 32)
        end
        shift = shift + 7
    end

    return UInt64(lo:tonumber(), hi:tonumber()), bytes_read
end

-- Decode a signed varint (zigzag encoding)
function pb.decode_sint(buffer, offset)
    local value, bytes_read = pb.decode_varint(buffer, offset)
    if value == nil then return nil, 0 end

    -- Zigzag decode
    if bit.band(value, 1) == 1 then
        return -bit.rshift(value + 1, 1), bytes_read
    else
        return bit.rshift(value, 1), bytes_read
    end
end

-- Decode a 32-bit fixed value
function pb.decode_fixed32(buffer, offset)
    if offset + 4 > buffer:len() then
        return nil, 0
    end
    return buffer:range(offset, 4):le_uint(), 4
end

-- Decode a 64-bit fixed value
function pb.decode_fixed64(buffer, offset)
    if offset + 8 > buffer:len() then
        return nil, 0
    end
    return buffer:range(offset, 8):le_uint64(), 8
end

-- Decode a float (32-bit)
function pb.decode_float(buffer, offset)
    if offset + 4 > buffer:len() then
        return nil, 0
    end
    return buffer:range(offset, 4):le_float(), 4
end

-- Decode a double (64-bit)
function pb.decode_double(buffer, offset)
    if offset + 8 > buffer:len() then
        return nil, 0
    end
    return buffer:range(offset, 8):le_float(), 8
end

-- Decode a length-delimited field (string, bytes, embedded message)
function pb.decode_length_delimited(buffer, offset)
    local length, varint_len = pb.decode_varint(buffer, offset)
    if length == nil then return nil, nil, 0 end

    if offset + varint_len + length > buffer:len() then
        return nil, nil, 0
    end

    local data = buffer:range(offset + varint_len, length)
    return data, length, varint_len + length
end

-- Decode field tag (field number and wire type)
function pb.decode_tag(buffer, offset)
    local tag, bytes_read = pb.decode_varint(buffer, offset)
    if tag == nil then return nil, nil, 0 end

    local field_number = bit.rshift(tag, 3)
    local wire_type = bit.band(tag, 0x07)

    return field_number, wire_type, bytes_read
end

-- Skip a field based on wire type
function pb.skip_field(buffer, offset, wire_type)
    if wire_type == pb.WIRE_VARINT then
        local _, bytes = pb.decode_varint(buffer, offset)
        return bytes
    elseif wire_type == pb.WIRE_64BIT then
        return 8
    elseif wire_type == pb.WIRE_LENGTH_DELIMITED then
        local _, _, bytes = pb.decode_length_delimited(buffer, offset)
        return bytes
    elseif wire_type == pb.WIRE_32BIT then
        return 4
    else
        return 0
    end
end

-- Parse all fields from a protobuf message
function pb.parse_message(buffer, offset, length)
    local fields = {}
    local end_offset = offset + length
    local pos = offset

    while pos < end_offset do
        local field_num, wire_type, tag_len = pb.decode_tag(buffer, pos)
        if field_num == nil then break end
        pos = pos + tag_len

        local field_data = nil
        local field_len = 0

        if wire_type == pb.WIRE_VARINT then
            field_data, field_len = pb.decode_varint(buffer, pos)
        elseif wire_type == pb.WIRE_64BIT then
            field_data, field_len = pb.decode_fixed64(buffer, pos)
        elseif wire_type == pb.WIRE_LENGTH_DELIMITED then
            local data, data_len, total_len = pb.decode_length_delimited(buffer, pos)
            field_data = data
            field_len = total_len
        elseif wire_type == pb.WIRE_32BIT then
            field_data, field_len = pb.decode_fixed32(buffer, pos)
        else
            break
        end

        if field_len == 0 then break end
        pos = pos + field_len

        -- Store field (handle repeated fields)
        if fields[field_num] == nil then
            fields[field_num] = {wire_type = wire_type, values = {}}
        end
        table.insert(fields[field_num].values, field_data)
    end

    return fields
end

-- Helper to get first value of a field
function pb.get_field(fields, field_num, default)
    if fields[field_num] and #fields[field_num].values > 0 then
        return fields[field_num].values[1]
    end
    return default
end

-- Helper to get string value
function pb.get_string(fields, field_num, default)
    local value = pb.get_field(fields, field_num, nil)
    if value and type(value) ~= "number" then
        return value:string()
    end
    return default or ""
end

-- Helper to get double value from length-delimited field
function pb.get_double(fields, field_num, default)
    local value = pb.get_field(fields, field_num, nil)
    if value and type(value) ~= "number" then
        if value:len() == 8 then
            return value:le_float()
        end
    elseif type(value) == "number" then
        return value
    end
    return default or 0.0
end

-- Helper to get uint64 value
function pb.get_uint64(fields, field_num, default)
    local value = pb.get_field(fields, field_num, nil)
    if value ~= nil then
        -- Return the value directly (could be number or UInt64 userdata)
        return value
    end
    return default
end

--------------------------------------------------------------------------------
-- XML Parser (Simple CoT XML extraction)
--------------------------------------------------------------------------------

local xml = {}

-- Extract attribute value from XML string
function xml.get_attr(str, attr_name)
    local pattern = attr_name .. "=['\"]([^'\"]*)['\"]"
    local value = string.match(str, pattern)
    return value
end

-- Extract element content
function xml.get_element(str, elem_name)
    local pattern = "<" .. elem_name .. "[^>]*>(.-)</" .. elem_name .. ">"
    return string.match(str, pattern)
end

-- Extract element with attributes
function xml.get_element_with_attrs(str, elem_name)
    local pattern = "<" .. elem_name .. "([^>]*)/?>"
    return string.match(str, pattern)
end

-- Check if string is likely XML
function xml.is_xml(str)
    return string.sub(str, 1, 5) == "<?xml" or string.sub(str, 1, 6) == "<event"
end

--------------------------------------------------------------------------------
-- Protocol Definition
--------------------------------------------------------------------------------

tak = Proto("TAK", "TAK Protocol")

-- Default settings - standard TAK ports
local default_settings = {
    -- Standard TAK ports
    port_default = 4242,      -- Default TCP/UDP
    port_sa_mcast = 6969,     -- SA Multicast (239.2.3.1:6969)
    port_sensor = 7171,       -- SA Multicast Sensor Data (239.5.5.55:7171)
    port_streaming = 8087,    -- Request/Notify (TCP) / Route Management (UDP)
    port_chat = 17012,        -- Chat Multicast (224.10.10.1:17012)
}

-- Preferences
tak.prefs.port_default = Pref.uint("Default Port", default_settings.port_default, "Default TCP/UDP port (4242)")
tak.prefs.port_sa_mcast = Pref.uint("SA Multicast Port", default_settings.port_sa_mcast, "SA Multicast port (6969)")
tak.prefs.port_sensor = Pref.uint("Sensor Data Port", default_settings.port_sensor, "Sensor data multicast port (7171)")
tak.prefs.port_streaming = Pref.uint("Streaming Port", default_settings.port_streaming, "Request/Notify/Route port (8087)")
tak.prefs.port_chat = Pref.uint("Chat Port", default_settings.port_chat, "Chat multicast port (17012)")

--------------------------------------------------------------------------------
-- Protocol Fields
--------------------------------------------------------------------------------

-- Common fields
tak.fields.protocol = ProtoField.string("tak.protocol", "Protocol")
tak.fields.version = ProtoField.uint8("tak.version", "Version", base.DEC)
tak.fields.length = ProtoField.uint32("tak.length", "Length", base.DEC)

-- TAK Message fields
tak.fields.tak_control = ProtoField.none("tak.control", "TAK Control")
tak.fields.tak_min_proto = ProtoField.uint32("tak.control.min_proto", "Min Protocol Version", base.DEC)
tak.fields.tak_max_proto = ProtoField.uint32("tak.control.max_proto", "Max Protocol Version", base.DEC)
tak.fields.tak_contact_uid = ProtoField.string("tak.control.contact_uid", "Contact UID")

-- CoT Event fields
tak.fields.cot_event = ProtoField.none("tak.cot", "CoT Event")
tak.fields.cot_type = ProtoField.string("tak.cot.type", "Type")
tak.fields.cot_uid = ProtoField.string("tak.cot.uid", "UID")
tak.fields.cot_how = ProtoField.string("tak.cot.how", "How")
tak.fields.cot_time = ProtoField.uint64("tak.cot.time", "Send Time", base.DEC)
tak.fields.cot_start = ProtoField.uint64("tak.cot.start", "Start Time", base.DEC)
tak.fields.cot_stale = ProtoField.uint64("tak.cot.stale", "Stale Time", base.DEC)
tak.fields.cot_access = ProtoField.string("tak.cot.access", "Access")
tak.fields.cot_qos = ProtoField.string("tak.cot.qos", "QoS")
tak.fields.cot_opex = ProtoField.string("tak.cot.opex", "Opex")

-- Point fields
tak.fields.point = ProtoField.none("tak.point", "Point")
tak.fields.lat = ProtoField.double("tak.point.lat", "Latitude")
tak.fields.lon = ProtoField.double("tak.point.lon", "Longitude")
tak.fields.hae = ProtoField.double("tak.point.hae", "HAE (Height Above Ellipsoid)")
tak.fields.ce = ProtoField.double("tak.point.ce", "CE (Circular Error)")
tak.fields.le = ProtoField.double("tak.point.le", "LE (Linear Error)")

-- Detail fields
tak.fields.detail = ProtoField.none("tak.detail", "Detail")
tak.fields.xml_detail = ProtoField.string("tak.detail.xml", "XML Detail")

-- Contact fields
tak.fields.contact = ProtoField.none("tak.detail.contact", "Contact")
tak.fields.contact_callsign = ProtoField.string("tak.detail.contact.callsign", "Callsign")
tak.fields.contact_endpoint = ProtoField.string("tak.detail.contact.endpoint", "Endpoint")

-- Group fields
tak.fields.group = ProtoField.none("tak.detail.group", "Group")
tak.fields.group_name = ProtoField.string("tak.detail.group.name", "Name")
tak.fields.group_role = ProtoField.string("tak.detail.group.role", "Role")

-- Status fields
tak.fields.status = ProtoField.none("tak.detail.status", "Status")
tak.fields.status_battery = ProtoField.uint32("tak.detail.status.battery", "Battery", base.DEC)

-- TAKv fields
tak.fields.takv = ProtoField.none("tak.detail.takv", "TAK Version")
tak.fields.takv_device = ProtoField.string("tak.detail.takv.device", "Device")
tak.fields.takv_platform = ProtoField.string("tak.detail.takv.platform", "Platform")
tak.fields.takv_os = ProtoField.string("tak.detail.takv.os", "OS")
tak.fields.takv_version = ProtoField.string("tak.detail.takv.version", "Version")

-- Track fields
tak.fields.track = ProtoField.none("tak.detail.track", "Track")
tak.fields.track_speed = ProtoField.double("tak.detail.track.speed", "Speed")
tak.fields.track_course = ProtoField.double("tak.detail.track.course", "Course")

-- Precision Location fields
tak.fields.precision = ProtoField.none("tak.detail.precision", "Precision Location")
tak.fields.precision_geopointsrc = ProtoField.string("tak.detail.precision.geopointsrc", "Geopoint Source")
tak.fields.precision_altsrc = ProtoField.string("tak.detail.precision.altsrc", "Altitude Source")

-- Expert info
tak.experts.malformed = ProtoExpert.new("tak.expert.malformed", "Malformed TAK Message", expert.group.MALFORMED, expert.severity.ERROR)
tak.experts.unsupported = ProtoExpert.new("tak.expert.unsupported", "Unsupported Message Type", expert.group.UNDECODED, expert.severity.WARN)

--------------------------------------------------------------------------------
-- TAK Protobuf Message Parsers
--------------------------------------------------------------------------------

-- Parse TakControl message (field numbers from takcontrol.proto)
local function parse_tak_control(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.tak_control, buffer:range(0, length))

    local min_proto = pb.get_field(fields, 1, 1)
    local max_proto = pb.get_field(fields, 2, 1)
    local contact_uid = pb.get_string(fields, 3)

    subtree:add(tak.fields.tak_min_proto, min_proto)
    subtree:add(tak.fields.tak_max_proto, max_proto)
    if contact_uid ~= "" then
        subtree:add(tak.fields.tak_contact_uid, contact_uid)
    end

    subtree:append_text(string.format(" (v%d-%d)", min_proto, max_proto))
    return contact_uid
end

-- Parse Contact message
local function parse_contact(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.contact, buffer:range(0, length))

    local endpoint = pb.get_string(fields, 1)
    local callsign = pb.get_string(fields, 2)

    if endpoint ~= "" then subtree:add(tak.fields.contact_endpoint, endpoint) end
    if callsign ~= "" then subtree:add(tak.fields.contact_callsign, callsign) end

    subtree:append_text(string.format(": %s", callsign))
    return callsign
end

-- Parse Group message
local function parse_group(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.group, buffer:range(0, length))

    local name = pb.get_string(fields, 1)
    local role = pb.get_string(fields, 2)

    if name ~= "" then subtree:add(tak.fields.group_name, name) end
    if role ~= "" then subtree:add(tak.fields.group_role, role) end

    subtree:append_text(string.format(": %s (%s)", name, role))
end

-- Parse Status message
local function parse_status(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.status, buffer:range(0, length))

    local battery = pb.get_field(fields, 1, 0)
    subtree:add(tak.fields.status_battery, battery)
    subtree:append_text(string.format(": Battery %d%%", battery))
end

-- Parse Takv message
local function parse_takv(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.takv, buffer:range(0, length))

    local device = pb.get_string(fields, 1)
    local platform = pb.get_string(fields, 2)
    local os = pb.get_string(fields, 3)
    local version = pb.get_string(fields, 4)

    if device ~= "" then subtree:add(tak.fields.takv_device, device) end
    if platform ~= "" then subtree:add(tak.fields.takv_platform, platform) end
    if os ~= "" then subtree:add(tak.fields.takv_os, os) end
    if version ~= "" then subtree:add(tak.fields.takv_version, version) end

    subtree:append_text(string.format(": %s %s", platform, version))
end

-- Parse Track message
local function parse_track(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.track, buffer:range(0, length))

    -- Track uses double fields (wire type 1 = fixed64 for doubles)
    local speed = 0.0
    local course = 0.0

    if fields[1] and fields[1].wire_type == pb.WIRE_64BIT then
        speed = buffer:range(0, 8):le_float()
    end
    if fields[2] then
        -- Find offset for field 2
        local pos = 0
        if fields[1] then pos = pos + 9 end -- tag + 8 bytes
        if pos + 9 <= length then
            course = buffer:range(pos + 1, 8):le_float()
        end
    end

    subtree:add(tak.fields.track_speed, speed)
    subtree:add(tak.fields.track_course, course)
    subtree:append_text(string.format(": Speed %.1f, Course %.1f", speed, course))
end

-- Parse PrecisionLocation message
local function parse_precision_location(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.precision, buffer:range(0, length))

    local geopointsrc = pb.get_string(fields, 1)
    local altsrc = pb.get_string(fields, 2)

    if geopointsrc ~= "" then subtree:add(tak.fields.precision_geopointsrc, geopointsrc) end
    if altsrc ~= "" then subtree:add(tak.fields.precision_altsrc, altsrc) end
end

-- Parse Detail message
local function parse_detail(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.detail, buffer:range(0, length))

    -- Field 1: xmlDetail (string)
    local xml_detail = pb.get_string(fields, 1)
    if xml_detail ~= "" then
        subtree:add(tak.fields.xml_detail, xml_detail)
    end

    -- Field 2: Contact
    if fields[2] then
        local data = fields[2].values[1]
        if data and type(data) ~= "number" then
            parse_contact(data:tvb("Contact"), data:len(), subtree)
        end
    end

    -- Field 3: Group
    if fields[3] then
        local data = fields[3].values[1]
        if data and type(data) ~= "number" then
            parse_group(data:tvb("Group"), data:len(), subtree)
        end
    end

    -- Field 4: PrecisionLocation
    if fields[4] then
        local data = fields[4].values[1]
        if data and type(data) ~= "number" then
            parse_precision_location(data:tvb("PrecisionLocation"), data:len(), subtree)
        end
    end

    -- Field 5: Status
    if fields[5] then
        local data = fields[5].values[1]
        if data and type(data) ~= "number" then
            parse_status(data:tvb("Status"), data:len(), subtree)
        end
    end

    -- Field 6: Takv
    if fields[6] then
        local data = fields[6].values[1]
        if data and type(data) ~= "number" then
            parse_takv(data:tvb("Takv"), data:len(), subtree)
        end
    end

    -- Field 7: Track
    if fields[7] then
        local data = fields[7].values[1]
        if data and type(data) ~= "number" then
            parse_track(data:tvb("Track"), data:len(), subtree)
        end
    end

    return xml_detail
end

-- Parse CotEvent message (field numbers from cotevent.proto)
local function parse_cot_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(tak.fields.cot_event, buffer:range(0, length))

    local cot_type = pb.get_string(fields, 1)
    local access = pb.get_string(fields, 2)
    local qos = pb.get_string(fields, 3)
    local opex = pb.get_string(fields, 4)
    local uid = pb.get_string(fields, 5)
    local send_time = pb.get_uint64(fields, 6, nil)
    local start_time = pb.get_uint64(fields, 7, nil)
    local stale_time = pb.get_uint64(fields, 8, nil)
    local how = pb.get_string(fields, 9)

    subtree:add(tak.fields.cot_type, cot_type)
    subtree:add(tak.fields.cot_uid, uid)
    if how ~= "" then subtree:add(tak.fields.cot_how, how) end
    if access ~= "" then subtree:add(tak.fields.cot_access, access) end
    if qos ~= "" then subtree:add(tak.fields.cot_qos, qos) end
    if opex ~= "" then subtree:add(tak.fields.cot_opex, opex) end
    if send_time ~= nil then subtree:add(tak.fields.cot_time, send_time) end
    if start_time ~= nil then subtree:add(tak.fields.cot_start, start_time) end
    if stale_time ~= nil then subtree:add(tak.fields.cot_stale, stale_time) end

    -- Point data (fields 10-14 are doubles)
    local point_tree = subtree:add(tak.fields.point)

    -- Parse doubles - need to extract from raw buffer
    local lat, lon, hae, ce, le = 0.0, 0.0, 0.0, 0.0, 0.0
    local pos = 0
    local buf_len = length

    while pos < buf_len do
        local field_num, wire_type, tag_len = pb.decode_tag(buffer, pos)
        if field_num == nil then break end
        pos = pos + tag_len

        if wire_type == pb.WIRE_64BIT and pos + 8 <= buf_len then
            local val = buffer:range(pos, 8):le_float()
            if field_num == 10 then lat = val
            elseif field_num == 11 then lon = val
            elseif field_num == 12 then hae = val
            elseif field_num == 13 then ce = val
            elseif field_num == 14 then le = val
            end
            pos = pos + 8
        elseif wire_type == pb.WIRE_VARINT then
            local _, vlen = pb.decode_varint(buffer, pos)
            pos = pos + vlen
        elseif wire_type == pb.WIRE_LENGTH_DELIMITED then
            local _, _, tlen = pb.decode_length_delimited(buffer, pos)
            pos = pos + tlen
        elseif wire_type == pb.WIRE_32BIT then
            pos = pos + 4
        else
            break
        end
    end

    point_tree:add(tak.fields.lat, lat)
    point_tree:add(tak.fields.lon, lon)
    point_tree:add(tak.fields.hae, hae)
    point_tree:add(tak.fields.ce, ce)
    point_tree:add(tak.fields.le, le)
    point_tree:append_text(string.format(": %.6f, %.6f", lat, lon))

    -- Field 15: Detail
    if fields[15] then
        local data = fields[15].values[1]
        if data and type(data) ~= "number" then
            parse_detail(data:tvb("Detail"), data:len(), subtree)
        end
    end

    subtree:append_text(string.format(": %s (%s)", cot_type, uid))
    return uid, cot_type
end

-- Parse TakMessage (top-level message)
local function parse_tak_message(buffer, length, tree, pinfo)
    local fields = pb.parse_message(buffer, 0, length)

    local uid = ""
    local cot_type = ""

    -- Field 1: TakControl
    if fields[1] then
        local data = fields[1].values[1]
        if data and type(data) ~= "number" then
            uid = parse_tak_control(data:tvb("TakControl"), data:len(), tree)
        end
    end

    -- Field 2: CotEvent
    if fields[2] then
        local data = fields[2].values[1]
        if data and type(data) ~= "number" then
            uid, cot_type = parse_cot_event(data:tvb("CotEvent"), data:len(), tree)
        end
    end

    -- Update info column
    if uid ~= "" then
        pinfo.cols.info:append(string.format(" [%s]", uid))
    end
    if cot_type ~= "" then
        pinfo.cols.info:append(string.format(" %s", cot_type))
    end
end

--------------------------------------------------------------------------------
-- XML CoT Parser
--------------------------------------------------------------------------------

local function parse_xml_cot(buffer, length, tree, pinfo)
    local xml_str = buffer:range(0, length):string()
    local subtree = tree:add(tak.fields.cot_event, buffer:range(0, length))

    -- Parse event attributes
    local event_attrs = xml.get_element_with_attrs(xml_str, "event")
    if event_attrs then
        local uid = xml.get_attr(event_attrs, "uid") or ""
        local cot_type = xml.get_attr(event_attrs, "type") or ""
        local how = xml.get_attr(event_attrs, "how") or ""
        local version = xml.get_attr(event_attrs, "version") or ""

        if cot_type ~= "" then subtree:add(tak.fields.cot_type, cot_type) end
        if uid ~= "" then subtree:add(tak.fields.cot_uid, uid) end
        if how ~= "" then subtree:add(tak.fields.cot_how, how) end

        subtree:append_text(string.format(": %s (%s)", cot_type, uid))

        pinfo.cols.info:append(string.format(" [%s] %s", uid, cot_type))
    end

    -- Parse point element
    local point_attrs = xml.get_element_with_attrs(xml_str, "point")
    if point_attrs then
        local point_tree = subtree:add(tak.fields.point)

        local lat = tonumber(xml.get_attr(point_attrs, "lat")) or 0
        local lon = tonumber(xml.get_attr(point_attrs, "lon")) or 0
        local hae = tonumber(xml.get_attr(point_attrs, "hae")) or 0
        local ce = tonumber(xml.get_attr(point_attrs, "ce")) or 0
        local le = tonumber(xml.get_attr(point_attrs, "le")) or 0

        point_tree:add(tak.fields.lat, lat)
        point_tree:add(tak.fields.lon, lon)
        point_tree:add(tak.fields.hae, hae)
        point_tree:add(tak.fields.ce, ce)
        point_tree:add(tak.fields.le, le)

        point_tree:append_text(string.format(": %.6f, %.6f", lat, lon))
    end

    -- Parse detail/contact
    local contact_attrs = xml.get_element_with_attrs(xml_str, "contact")
    if contact_attrs then
        local contact_tree = subtree:add(tak.fields.contact)
        local callsign = xml.get_attr(contact_attrs, "callsign") or ""
        local endpoint = xml.get_attr(contact_attrs, "endpoint") or ""

        if callsign ~= "" then contact_tree:add(tak.fields.contact_callsign, callsign) end
        if endpoint ~= "" then contact_tree:add(tak.fields.contact_endpoint, endpoint) end

        contact_tree:append_text(string.format(": %s", callsign))
    end

    -- Parse detail/__group
    local group_attrs = xml.get_element_with_attrs(xml_str, "__group")
    if group_attrs then
        local group_tree = subtree:add(tak.fields.group)
        local name = xml.get_attr(group_attrs, "name") or ""
        local role = xml.get_attr(group_attrs, "role") or ""

        if name ~= "" then group_tree:add(tak.fields.group_name, name) end
        if role ~= "" then group_tree:add(tak.fields.group_role, role) end

        group_tree:append_text(string.format(": %s (%s)", name, role))
    end

    -- Parse detail/takv
    local takv_attrs = xml.get_element_with_attrs(xml_str, "takv")
    if takv_attrs then
        local takv_tree = subtree:add(tak.fields.takv)
        local device = xml.get_attr(takv_attrs, "device") or ""
        local platform = xml.get_attr(takv_attrs, "platform") or ""
        local os = xml.get_attr(takv_attrs, "os") or ""
        local version = xml.get_attr(takv_attrs, "version") or ""

        if device ~= "" then takv_tree:add(tak.fields.takv_device, device) end
        if platform ~= "" then takv_tree:add(tak.fields.takv_platform, platform) end
        if os ~= "" then takv_tree:add(tak.fields.takv_os, os) end
        if version ~= "" then takv_tree:add(tak.fields.takv_version, version) end

        takv_tree:append_text(string.format(": %s %s", platform, version))
    end

    -- Parse detail/track
    local track_attrs = xml.get_element_with_attrs(xml_str, "track")
    if track_attrs then
        local track_tree = subtree:add(tak.fields.track)
        local speed = tonumber(xml.get_attr(track_attrs, "speed")) or 0
        local course = tonumber(xml.get_attr(track_attrs, "course")) or 0

        track_tree:add(tak.fields.track_speed, speed)
        track_tree:add(tak.fields.track_course, course)

        track_tree:append_text(string.format(": Speed %.1f, Course %.1f", speed, course))
    end

    -- Parse detail/status
    local status_attrs = xml.get_element_with_attrs(xml_str, "status")
    if status_attrs then
        local status_tree = subtree:add(tak.fields.status)
        local battery = tonumber(xml.get_attr(status_attrs, "battery")) or 0

        status_tree:add(tak.fields.status_battery, battery)
        status_tree:append_text(string.format(": Battery %d%%", battery))
    end

    -- Parse detail/precisionlocation
    local precision_attrs = xml.get_element_with_attrs(xml_str, "precisionlocation")
    if precision_attrs then
        local prec_tree = subtree:add(tak.fields.precision)
        local geopointsrc = xml.get_attr(precision_attrs, "geopointsrc") or ""
        local altsrc = xml.get_attr(precision_attrs, "altsrc") or ""

        if geopointsrc ~= "" then prec_tree:add(tak.fields.precision_geopointsrc, geopointsrc) end
        if altsrc ~= "" then prec_tree:add(tak.fields.precision_altsrc, altsrc) end
    end
end

--------------------------------------------------------------------------------
-- Main Dissector
--------------------------------------------------------------------------------

-- Decode TAK protocol varint (same as protobuf varint)
local function tak_varint(buffer, offset)
    return pb.decode_varint(buffer, offset)
end

tak.dissector = function(buffer, pinfo, tree)
    local offset = 0
    local length = buffer:reported_length_remaining()
    local subtree = tree:add(tak, buffer:range(0, length), "TAK Message")

    pinfo.cols.protocol:set(tak.name)
    pinfo.cols.info:set("TAK")

    -- Check for XML CoT message
    if length >= 5 and buffer:range(0, 5):string() == "<?xml" then
        local version = 0
        local protocol = "xml"

        subtree:add(tak.fields.version, version)
        subtree:add(tak.fields.length, length)
        subtree:add(tak.fields.protocol, protocol)
        subtree:append_text(string.format(", Version: %d, Length: %d, Protocol: %s", version, length, protocol))

        pinfo.cols.info:set("TAK/XML")
        parse_xml_cot(buffer, length, subtree, pinfo)
        return length
    end

    -- Check for XML CoT without declaration
    if length >= 6 and buffer:range(0, 6):string() == "<event" then
        local version = 0
        local protocol = "xml"

        subtree:add(tak.fields.version, version)
        subtree:add(tak.fields.length, length)
        subtree:add(tak.fields.protocol, protocol)
        subtree:append_text(string.format(", Version: %d, Length: %d, Protocol: %s", version, length, protocol))

        pinfo.cols.info:set("TAK/XML")
        parse_xml_cot(buffer, length, subtree, pinfo)
        return length
    end

    -- Check for TAK magic byte (0xBF)
    if buffer:range(0, 1):uint() == 0xBF then
        offset = 1

        -- Decode first varint (length or version)
        local varint_val, varint_len = tak_varint(buffer, offset)
        if varint_val == nil then
            subtree:add_proto_expert_info(tak.experts.malformed, "Failed to decode varint")
            return 0
        end
        offset = offset + varint_len

        -- Check for second magic byte
        if offset < length and buffer:range(offset, 1):uint() == 0xBF then
            -- Mesh protocol (version 2+)
            local version = varint_val
            local protocol = "mesh"
            offset = offset + 1

            local payload_length = length - offset

            subtree:add(tak.fields.version, version)
            subtree:add(tak.fields.length, payload_length)
            subtree:add(tak.fields.protocol, protocol)
            subtree:append_text(string.format(", Version: %d, Length: %d, Protocol: %s", version, payload_length, protocol))

            pinfo.cols.info:set(string.format("TAK/Mesh v%d", version))

            -- Parse protobuf payload
            if payload_length > 0 then
                parse_tak_message(buffer:range(offset, payload_length):tvb("TakMessage"), payload_length, subtree, pinfo)
            end
        else
            -- Stream protocol (version 1)
            local version = 1
            local protocol = "stream"
            local payload_length = varint_val

            if payload_length ~= (length - offset) then
                subtree:add_proto_expert_info(tak.experts.malformed, "Payload length mismatch")
                return 0
            end

            subtree:add(tak.fields.version, version)
            subtree:add(tak.fields.length, payload_length)
            subtree:add(tak.fields.protocol, protocol)
            subtree:append_text(string.format(", Version: %d, Length: %d, Protocol: %s", version, payload_length, protocol))

            pinfo.cols.info:set("TAK/Stream")

            -- Parse protobuf payload
            if payload_length > 0 then
                parse_tak_message(buffer:range(offset, payload_length):tvb("TakMessage"), payload_length, subtree, pinfo)
            end
        end

        return length
    end

    -- Unknown format
    subtree:add_proto_expert_info(tak.experts.unsupported, "Unknown message format")
    return 0
end

--------------------------------------------------------------------------------
-- Preference Change Handler
--------------------------------------------------------------------------------

-- Helper to register/unregister a port
local function register_port(port)
    if port ~= 0 then
        DissectorTable.get("tcp.port"):add(port, tak)
        DissectorTable.get("udp.port"):add(port, tak)
        pcall(function()
            DissectorTable.get("quic.port"):add(port, tak)
        end)
    end
end

local function unregister_port(port)
    if port ~= 0 then
        DissectorTable.get("tcp.port"):remove(port, tak)
        DissectorTable.get("udp.port"):remove(port, tak)
        pcall(function()
            DissectorTable.get("quic.port"):remove(port, tak)
        end)
    end
end

tak.prefs_changed = function()
    -- Update port registrations when preferences change
    local port_prefs = {
        {setting = "port_default", pref = tak.prefs.port_default},
        {setting = "port_sa_mcast", pref = tak.prefs.port_sa_mcast},
        {setting = "port_sensor", pref = tak.prefs.port_sensor},
        {setting = "port_streaming", pref = tak.prefs.port_streaming},
        {setting = "port_chat", pref = tak.prefs.port_chat},
    }

    for _, p in ipairs(port_prefs) do
        if default_settings[p.setting] ~= p.pref then
            unregister_port(default_settings[p.setting])
            default_settings[p.setting] = p.pref
            register_port(p.pref)
        end
    end
end

--------------------------------------------------------------------------------
-- Register Dissector
--------------------------------------------------------------------------------

-- Register for TCP, UDP (includes multicast), and QUIC on all standard TAK ports
register_port(default_settings.port_default)   -- 4242
register_port(default_settings.port_sa_mcast)  -- 6969
register_port(default_settings.port_sensor)    -- 7171
register_port(default_settings.port_streaming) -- 8087
register_port(default_settings.port_chat)      -- 17012
