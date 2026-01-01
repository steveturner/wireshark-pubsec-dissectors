-- OMNI Protocol Plugin
-- Supports: Open Mission Network Interface protocol
-- No external dependencies required - native protobuf parsing included

-- Metadata
set_plugin_info({
    description = "Wireshark plugin for OMNI protocol.",
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
function pb.decode_varint(buffer, offset)
    local value = 0
    local shift = 0
    local bytes_read = 0

    while true do
        if offset + bytes_read >= buffer:len() then
            return nil, 0
        end

        local byte = buffer:range(offset + bytes_read, 1):uint()
        bytes_read = bytes_read + 1

        value = value + bit.lshift(bit.band(byte, 0x7f), shift)
        shift = shift + 7

        if bit.band(byte, 0x80) == 0 then
            break
        end

        if bytes_read > 10 then
            return nil, 0
        end
    end

    return value, bytes_read
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
    if value == nil then
        return default or 0.0
    end

    -- Handle TvbRange (length-delimited bytes containing a double)
    if type(value) == "userdata" then
        -- Check if it's a TvbRange by trying to get length
        local ok, len = pcall(function() return value:len() end)
        if ok and len == 8 then
            return value:le_float()
        end
        -- Could be a UInt64 from fixed64 wire type
        local ok2, num = pcall(function() return value:tonumber() end)
        if ok2 then
            return num
        end
    elseif type(value) == "number" then
        return value
    end
    return default or 0.0
end

-- Helper to get uint64 value
function pb.get_uint64(fields, field_num, default)
    local value = pb.get_field(fields, field_num, nil)
    if value then
        if type(value) == "number" then
            return value
        end
    end
    return default or 0
end

--------------------------------------------------------------------------------
-- Protocol Definition
--------------------------------------------------------------------------------

omni = Proto("OMNI", "OMNI Protocol")

-- Default settings
local default_settings = {
    port = 8089,
}

-- Preferences
omni.prefs.port = Pref.uint("OMNI Port", default_settings.port, "TCP/UDP port for OMNI messages")

--------------------------------------------------------------------------------
-- Protocol Fields
--------------------------------------------------------------------------------

-- Common fields
omni.fields.protocol = ProtoField.string("omni.protocol", "Protocol")
omni.fields.version = ProtoField.uint8("omni.version", "Version", base.DEC)
omni.fields.length = ProtoField.uint32("omni.length", "Length", base.DEC)

-- OMNI BaseEvent fields
omni.fields.base_event = ProtoField.none("omni.event", "OMNI Event")
omni.fields.entity_id = ProtoField.string("omni.entity_id", "Entity ID")
omni.fields.seq_num = ProtoField.string("omni.seq_num", "Sequence Number")
omni.fields.event_type = ProtoField.string("omni.event_type", "Event Type")

-- OMNI Origin fields
omni.fields.origin = ProtoField.none("omni.origin", "Origin")
omni.fields.source_uid = ProtoField.string("omni.origin.source_uid", "Source UID")
omni.fields.source_net = ProtoField.string("omni.origin.source_net", "Source Network")

-- OMNI Time fields
omni.fields.time = ProtoField.none("omni.time", "Time of Validity")
omni.fields.time_created = ProtoField.uint64("omni.time.created", "Created", base.DEC)
omni.fields.time_updated = ProtoField.uint32("omni.time.updated", "Updated (ms)", base.DEC)
omni.fields.time_timeout = ProtoField.uint32("omni.time.timeout", "Timeout (ms)", base.DEC)

-- OMNI Alias fields
omni.fields.alias = ProtoField.none("omni.alias", "Alias")
omni.fields.alias_domain = ProtoField.string("omni.alias.domain", "Domain")
omni.fields.alias_field = ProtoField.string("omni.alias.field", "Field")
omni.fields.alias_network = ProtoField.string("omni.alias.network", "Network")
omni.fields.alias_id = ProtoField.string("omni.alias.id", "ID")

-- OMNI Track Event fields
omni.fields.track = ProtoField.none("omni.track", "Track Event")
omni.fields.track_lat = ProtoField.double("omni.track.lat", "Latitude")
omni.fields.track_lon = ProtoField.double("omni.track.lon", "Longitude")
omni.fields.track_alt = ProtoField.double("omni.track.alt", "Altitude")
omni.fields.track_speed = ProtoField.double("omni.track.speed", "Speed")
omni.fields.track_course = ProtoField.double("omni.track.course", "Course")

-- OMNI Player Event fields
omni.fields.player = ProtoField.none("omni.player", "Player Event")
omni.fields.player_callsign = ProtoField.string("omni.player.callsign", "Callsign")

-- OMNI Chat Event fields
omni.fields.chat = ProtoField.none("omni.chat", "Chat Event")
omni.fields.chat_sender = ProtoField.string("omni.chat.sender", "Sender")
omni.fields.chat_message = ProtoField.string("omni.chat.message", "Message")

-- OMNI Sensor Event fields
omni.fields.sensor = ProtoField.none("omni.sensor", "Sensor Event")
omni.fields.sensor_status = ProtoField.string("omni.sensor.status", "Status")
omni.fields.sensor_lat = ProtoField.double("omni.sensor.lat", "Latitude")
omni.fields.sensor_lon = ProtoField.double("omni.sensor.lon", "Longitude")

-- OMNI Shape Event fields
omni.fields.shape = ProtoField.none("omni.shape", "Shape Event")
omni.fields.shape_type = ProtoField.string("omni.shape.type", "Shape Type")
omni.fields.shape_environment = ProtoField.string("omni.shape.environment", "Environment")
omni.fields.shape_identity = ProtoField.string("omni.shape.identity", "Identity")

-- OMNI Mission Assignment Event fields
omni.fields.mission = ProtoField.none("omni.mission", "Mission Assignment Event")
omni.fields.mission_type = ProtoField.string("omni.mission.type", "Mission Type")
omni.fields.mission_source = ProtoField.string("omni.mission.source", "Source ID")
omni.fields.mission_addressee = ProtoField.string("omni.mission.addressee", "Addressee ID")

-- OMNI Weather Event fields
omni.fields.weather = ProtoField.none("omni.weather", "Weather Event")
omni.fields.weather_category = ProtoField.string("omni.weather.category", "Category")

-- OMNI Airfield Status Event fields
omni.fields.airfield = ProtoField.none("omni.airfield", "Airfield Status Event")
omni.fields.airfield_icao = ProtoField.string("omni.airfield.icao", "ICAO Code")
omni.fields.airfield_status = ProtoField.string("omni.airfield.status", "Status")

-- OMNI Personnel Recovery Event fields
omni.fields.pr = ProtoField.none("omni.pr", "Personnel Recovery Event")
omni.fields.pr_type = ProtoField.string("omni.pr.type", "PR Type")
omni.fields.pr_status = ProtoField.string("omni.pr.status", "Status")

-- OMNI Entity Management Event fields
omni.fields.entity_mgmt = ProtoField.none("omni.entity_mgmt", "Entity Management Event")
omni.fields.entity_mgmt_action = ProtoField.string("omni.entity_mgmt.action", "Action")

-- OMNI Network Management Event fields
omni.fields.network_mgmt = ProtoField.none("omni.network_mgmt", "Network Management Event")
omni.fields.network_mgmt_type = ProtoField.string("omni.network_mgmt.type", "Type")
omni.fields.network_mgmt_message = ProtoField.string("omni.network_mgmt.message", "Message")

-- OMNI Navigation Vector Event fields
omni.fields.nav_vector = ProtoField.none("omni.nav_vector", "Navigation Vector Event")
omni.fields.nav_course = ProtoField.double("omni.nav_vector.course", "Course")
omni.fields.nav_speed = ProtoField.double("omni.nav_vector.speed", "Speed")
omni.fields.nav_altitude = ProtoField.double("omni.nav_vector.altitude", "Altitude")

-- OMNI Image Event fields
omni.fields.image = ProtoField.none("omni.image", "Image Event")
omni.fields.image_lat = ProtoField.double("omni.image.lat", "Latitude")
omni.fields.image_lon = ProtoField.double("omni.image.lon", "Longitude")

-- OMNI Alert Event fields
omni.fields.alert = ProtoField.none("omni.alert", "Alert Event")
omni.fields.alert_message = ProtoField.string("omni.alert.message", "Message")
omni.fields.alert_category = ProtoField.string("omni.alert.category", "Category")
omni.fields.alert_state = ProtoField.string("omni.alert.state", "State")
omni.fields.alert_type = ProtoField.string("omni.alert.type", "Type")

-- OMNI Flight Path Event fields
omni.fields.flight_path = ProtoField.none("omni.flight_path", "Flight Path Event")
omni.fields.flight_path_seq = ProtoField.uint32("omni.flight_path.sequence", "Sequence Number")
omni.fields.flight_path_points = ProtoField.uint32("omni.flight_path.total_points", "Total Points")

-- OMNI Geopoint fields (shared by multiple events)
omni.fields.geopoint = ProtoField.none("omni.geopoint", "Geopoint")
omni.fields.geopoint_lat = ProtoField.double("omni.geopoint.lat", "Latitude")
omni.fields.geopoint_lon = ProtoField.double("omni.geopoint.lon", "Longitude")
omni.fields.geopoint_hae = ProtoField.double("omni.geopoint.hae", "Height Above Ellipsoid")
omni.fields.geopoint_ce = ProtoField.double("omni.geopoint.ce", "Circular Error")
omni.fields.geopoint_le = ProtoField.double("omni.geopoint.le", "Linear Error")
omni.fields.geopoint_course = ProtoField.double("omni.geopoint.course", "Course")
omni.fields.geopoint_speed = ProtoField.double("omni.geopoint.speed", "Speed")

-- Expert info
omni.experts.malformed = ProtoExpert.new("omni.expert.malformed", "Malformed OMNI Message", expert.group.MALFORMED, expert.severity.ERROR)
omni.experts.unsupported = ProtoExpert.new("omni.expert.unsupported", "Unsupported Message Type", expert.group.UNDECODED, expert.severity.WARN)

--------------------------------------------------------------------------------
-- OMNI Protobuf Message Parsers
--------------------------------------------------------------------------------

-- Parse OMNI Alias message
local function parse_omni_alias(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.alias, buffer:range(0, length))

    local domain = pb.get_string(fields, 1)
    local field = pb.get_string(fields, 2)
    local network = pb.get_string(fields, 3)
    local id = pb.get_string(fields, 4)

    if domain ~= "" then subtree:add(omni.fields.alias_domain, domain) end
    if field ~= "" then subtree:add(omni.fields.alias_field, field) end
    if network ~= "" then subtree:add(omni.fields.alias_network, network) end
    if id ~= "" then subtree:add(omni.fields.alias_id, id) end

    subtree:append_text(string.format(": %s", id))
    return id
end

-- Parse OMNI EventOrigin message
local function parse_omni_origin(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.origin, buffer:range(0, length))

    local source_uid = pb.get_string(fields, 1)
    local source_net = pb.get_string(fields, 2)

    if source_uid ~= "" then subtree:add(omni.fields.source_uid, source_uid) end
    if source_net ~= "" then subtree:add(omni.fields.source_net, source_net) end

    subtree:append_text(string.format(": %s", source_uid))
    return source_uid
end

-- Parse OMNI TimeOfValidity message
local function parse_omni_time(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.time, buffer:range(0, length))

    -- Field 1 is a google.protobuf.Timestamp (embedded message)
    -- Fields 2, 3 are uint32
    local updated = pb.get_field(fields, 2, 0)
    local timeout = pb.get_field(fields, 3, 0)

    if type(updated) == "number" then subtree:add(omni.fields.time_updated, updated) end
    if type(timeout) == "number" then subtree:add(omni.fields.time_timeout, timeout) end
end

-- Parse OMNI TrackEvent message (field numbers from trackevent.proto)
local function parse_omni_track_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.track, buffer:range(0, length))

    -- GeoPoint is typically field 1, contains lat/lon/alt
    if fields[1] then
        local data = fields[1].values[1]
        if data and type(data) ~= "number" then
            local geo_fields = pb.parse_message(data:tvb("GeoPoint"), 0, data:len())
            -- GeoPoint fields: 1=lat, 2=lon, 3=alt (as doubles)
        end
    end

    subtree:append_text(": Track Event")
    return "Track"
end

-- Parse OMNI PlayerEvent message
local function parse_omni_player_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.player, buffer:range(0, length))

    -- Parse communication parameters for callsign
    if fields[1] then
        local data = fields[1].values[1]
        if data and type(data) ~= "number" then
            local comm_fields = pb.parse_message(data:tvb("CommParams"), 0, data:len())
            local callsign = pb.get_string(comm_fields, 1)
            if callsign ~= "" then
                subtree:add(omni.fields.player_callsign, callsign)
                subtree:append_text(string.format(": %s", callsign))
                return callsign
            end
        end
    end

    subtree:append_text(": Player Event")
    return "Player"
end

-- Parse OMNI ChatEvent message
local function parse_omni_chat_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.chat, buffer:range(0, length))

    local message = pb.get_string(fields, 1)
    local attachment = pb.get_string(fields, 2)

    if message ~= "" then subtree:add(omni.fields.chat_message, message) end

    -- Parse source alias (field 3)
    local sender = ""
    if fields[3] then
        local data = fields[3].values[1]
        if data and type(data) ~= "number" then
            local alias_fields = pb.parse_message(data:tvb("Alias"), 0, data:len())
            sender = pb.get_string(alias_fields, 4) -- id field
            if sender ~= "" then subtree:add(omni.fields.chat_sender, sender) end
        end
    end

    subtree:append_text(string.format(": %s", message ~= "" and message or "Chat"))
    return message
end

-- Parse Geopoint message (shared helper)
local function parse_geopoint(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.geopoint, buffer:range(0, length))

    local lat = pb.get_double(fields, 1, 0.0)
    local lon = pb.get_double(fields, 2, 0.0)

    subtree:add(omni.fields.geopoint_lat, lat)
    subtree:add(omni.fields.geopoint_lon, lon)

    -- HAE (field 3) - wrapper message
    if fields[3] then
        local data = fields[3].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("HAE"), 0, data:len())
            local hae = pb.get_double(wrapper, 1, 0.0)
            subtree:add(omni.fields.geopoint_hae, hae)
        end
    end

    -- Circular Error (field 4), Linear Error (field 5)
    if fields[4] then
        local data = fields[4].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("CE"), 0, data:len())
            local ce = pb.get_double(wrapper, 1, 0.0)
            subtree:add(omni.fields.geopoint_ce, ce)
        end
    end

    -- Course (field 6), Speed (field 7)
    if fields[6] then
        local data = fields[6].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("Course"), 0, data:len())
            local course = pb.get_double(wrapper, 1, 0.0)
            subtree:add(omni.fields.geopoint_course, course)
        end
    end
    if fields[7] then
        local data = fields[7].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("Speed"), 0, data:len())
            local speed = pb.get_double(wrapper, 1, 0.0)
            subtree:add(omni.fields.geopoint_speed, speed)
        end
    end

    subtree:append_text(string.format(": %.6f, %.6f", lat, lon))
    return lat, lon
end

-- Sensor status enum values
local sensor_status_values = {
    [0] = "NO_STATEMENT",
    [1] = "OPERATIONAL",
    [2] = "DEGRADED",
    [3] = "INOPERATIVE",
}

-- Parse OMNI SensorEvent message (field 14)
local function parse_omni_sensor_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.sensor, buffer:range(0, length))

    -- Field 2: Geopoint
    local lat, lon = 0, 0
    if fields[2] then
        local data = fields[2].values[1]
        if data and type(data) ~= "number" then
            lat, lon = parse_geopoint(data:tvb("Geopoint"), data:len(), subtree)
        end
    end

    -- Field 3: SensorStatus (oneof)
    if fields[3] then
        local status = pb.get_field(fields, 3, 0)
        local status_name = sensor_status_values[status] or tostring(status)
        subtree:add(omni.fields.sensor_status, status_name)
    end

    subtree:append_text(": Sensor Event")
    return "Sensor"
end

-- Shape type names based on oneof field numbers
local shape_type_names = {
    [1] = "SinglePoint",
    [2] = "Ellipse",
    [3] = "Rectangle",
    [4] = "Polyline",
    [5] = "Polygon",
    [6] = "PolyArc",
    [7] = "RadArc",
}

-- Environment category enum
local environment_values = {
    [0] = "NO_STATEMENT",
    [1] = "SURFACE",
    [2] = "SUBSURFACE",
    [3] = "AIR",
    [4] = "SPACE",
    [5] = "LAND_UNIT",
    [6] = "LAND_INSTALLATION",
}

-- Identity affiliation enum
local identity_values = {
    [0] = "NO_STATEMENT_IA",
    [1] = "PENDING",
    [2] = "UNKNOWN",
    [3] = "ASSUMED_FRIEND",
    [4] = "FRIEND",
    [5] = "NEUTRAL",
    [6] = "SUSPECT",
    [7] = "HOSTILE",
}

-- Parse OMNI ShapeEvent message (field 15)
local function parse_omni_shape_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.shape, buffer:range(0, length))

    -- Detect shape type from oneof (fields 1-7)
    local shape_type = "Unknown"
    for field_num, type_name in pairs(shape_type_names) do
        if fields[field_num] then
            shape_type = type_name
            subtree:add(omni.fields.shape_type, type_name)
            break
        end
    end

    -- Field 8: Environment category
    if fields[8] then
        local env = pb.get_field(fields, 8, 0)
        local env_name = environment_values[env] or tostring(env)
        subtree:add(omni.fields.shape_environment, env_name)
    end

    -- Field 9: Identity affiliation
    if fields[9] then
        local identity = pb.get_field(fields, 9, 0)
        local identity_name = identity_values[identity] or tostring(identity)
        subtree:add(omni.fields.shape_identity, identity_name)
    end

    subtree:append_text(string.format(": %s", shape_type))
    return shape_type
end

-- Mission assignment type enum
local mission_type_values = {
    [0] = "NO_STATEMENT",
    [1] = "SURVEILLANCE",
    [2] = "AIR_COVER",
    [3] = "ESCORT",
    [4] = "ATTACK",
    [5] = "COMBAT_AIR_PATROL",
    [6] = "INTERCEPT",
    [7] = "INVESTIGATE",
    [8] = "TRACK",
    [9] = "GO_TO",
    [10] = "PROVIDE_FIRE_SUPPORT",
    [11] = "SEARCH_AND_RESCUE",
    [12] = "TANKER",
    [13] = "COMMAND_AND_CONTROL",
}

-- Parse OMNI MissionAssignmentEvent message (field 17)
local function parse_omni_mission_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.mission, buffer:range(0, length))

    -- Field 1: Mission type
    if fields[1] then
        local mtype = pb.get_field(fields, 1, 0)
        local type_name = mission_type_values[mtype] or tostring(mtype)
        subtree:add(omni.fields.mission_type, type_name)
    end

    -- Field 2: Source alias
    if fields[2] then
        local data = fields[2].values[1]
        if data and type(data) ~= "number" then
            local alias_fields = pb.parse_message(data:tvb("SourceAlias"), 0, data:len())
            local source_id = pb.get_string(alias_fields, 4)
            if source_id ~= "" then subtree:add(omni.fields.mission_source, source_id) end
        end
    end

    -- Field 3: Addressee alias
    if fields[3] then
        local data = fields[3].values[1]
        if data and type(data) ~= "number" then
            local alias_fields = pb.parse_message(data:tvb("AddresseeAlias"), 0, data:len())
            local addressee_id = pb.get_string(alias_fields, 4)
            if addressee_id ~= "" then subtree:add(omni.fields.mission_addressee, addressee_id) end
        end
    end

    subtree:append_text(": Mission Assignment")
    return "MissionAssignment"
end

-- Parse OMNI WeatherEvent message (field 20)
local function parse_omni_weather_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.weather, buffer:range(0, length))

    -- Field 1: Category
    if fields[1] then
        local category = pb.get_field(fields, 1, 0)
        subtree:add(omni.fields.weather_category, tostring(category))
    end

    subtree:append_text(": Weather Event")
    return "Weather"
end

-- Parse OMNI AirfieldStatusEvent message (field 22)
local function parse_omni_airfield_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.airfield, buffer:range(0, length))

    -- Field 1: ICAO code
    local icao = pb.get_string(fields, 1)
    if icao ~= "" then subtree:add(omni.fields.airfield_icao, icao) end

    -- Field 2: Status enum
    if fields[2] then
        local status = pb.get_field(fields, 2, 0)
        subtree:add(omni.fields.airfield_status, tostring(status))
    end

    subtree:append_text(string.format(": %s", icao ~= "" and icao or "Airfield"))
    return icao
end

-- Personnel recovery event type enum
local pr_type_values = {
    [0] = "NO_STATEMENT",
    [1] = "AUTHENTICATE",
    [2] = "ACKNOWLEDGE",
    [3] = "REQUEST",
    [4] = "INITIATE",
    [5] = "TERMINATION",
    [6] = "UPDATE",
    [7] = "SITUATION_REPORT",
}

-- Parse OMNI PersonnelRecoveryEvent message (field 23)
local function parse_omni_pr_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.pr, buffer:range(0, length))

    -- Field 1: PR Type
    if fields[1] then
        local prtype = pb.get_field(fields, 1, 0)
        local type_name = pr_type_values[prtype] or tostring(prtype)
        subtree:add(omni.fields.pr_type, type_name)
    end

    subtree:append_text(": Personnel Recovery")
    return "PersonnelRecovery"
end

-- Entity management action enum
local entity_mgmt_actions = {
    [0] = "NO_STATEMENT",
    [1] = "DROP",
    [2] = "LINK",
    [3] = "UNLINK",
    [4] = "ALIAS_UPDATE",
}

-- Parse OMNI EntityManagementEvent message (field 25)
local function parse_omni_entity_mgmt_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.entity_mgmt, buffer:range(0, length))

    -- Detect action type from oneof fields
    local action = "Unknown"
    if fields[1] then
        action = "Drop"
    elseif fields[2] then
        action = "Link"
    elseif fields[3] then
        action = "Unlink"
    elseif fields[4] then
        action = "AliasUpdate"
    end

    subtree:add(omni.fields.entity_mgmt_action, action)
    subtree:append_text(string.format(": %s", action))
    return action
end

-- Network management type enum
local network_mgmt_types = {
    [1] = "Ping",
    [2] = "Terminate",
    [3] = "Error",
    [4] = "ServerDiscovery",
}

-- Parse OMNI NetworkManagementEvent message (field 26)
local function parse_omni_network_mgmt_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.network_mgmt, buffer:range(0, length))

    -- Detect type from oneof fields (1-4)
    local mgmt_type = "Unknown"
    for field_num, type_name in pairs(network_mgmt_types) do
        if fields[field_num] then
            mgmt_type = type_name
            subtree:add(omni.fields.network_mgmt_type, type_name)

            -- For Error type (field 3), parse error message
            if field_num == 3 then
                local data = fields[field_num].values[1]
                if data and type(data) ~= "number" then
                    local err_fields = pb.parse_message(data:tvb("Error"), 0, data:len())
                    local msg = pb.get_string(err_fields, 2)
                    if msg ~= "" then subtree:add(omni.fields.network_mgmt_message, msg) end
                end
            end
            break
        end
    end

    subtree:append_text(string.format(": %s", mgmt_type))
    return mgmt_type
end

-- Parse OMNI NavigationVectorEvent message (field 29)
local function parse_omni_nav_vector_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.nav_vector, buffer:range(0, length))

    -- Parse navigation data from wrapper messages
    if fields[1] then
        local data = fields[1].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("Course"), 0, data:len())
            local course = pb.get_double(wrapper, 1, 0.0)
            subtree:add(omni.fields.nav_course, course)
        end
    end

    if fields[2] then
        local data = fields[2].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("Speed"), 0, data:len())
            local speed = pb.get_double(wrapper, 1, 0.0)
            subtree:add(omni.fields.nav_speed, speed)
        end
    end

    if fields[3] then
        local data = fields[3].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("Altitude"), 0, data:len())
            local alt = pb.get_double(wrapper, 1, 0.0)
            subtree:add(omni.fields.nav_altitude, alt)
        end
    end

    subtree:append_text(": Navigation Vector")
    return "NavigationVector"
end

-- Parse OMNI ImageEvent message (field 36)
local function parse_omni_image_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.image, buffer:range(0, length))

    -- Field 2: Geopoint location
    if fields[2] then
        local data = fields[2].values[1]
        if data and type(data) ~= "number" then
            parse_geopoint(data:tvb("Location"), data:len(), subtree)
        end
    end

    subtree:append_text(": Image Event")
    return "Image"
end

-- Alert category enum
local alert_category_values = {
    [0] = "UNKNOWN",
    [1] = "CAT_1 (Critical)",
    [2] = "CAT_2 (Major)",
    [3] = "CAT_3 (Routine)",
    [4] = "CAT_4 (Syntax Error)",
}

-- Alert state enum
local alert_state_values = {
    [0] = "CLOSED",
    [1] = "AWAITING_RESPONSE",
    [2] = "ACTIVE",
    [3] = "TIMED_OUT",
    [4] = "INVALID_RESPONSE",
}

-- Alert type enum (abbreviated)
local alert_type_values = {
    [0] = "NO_STATEMENT",
    [1] = "OTHER",
    [2] = "BAILOUT",
    [3] = "MISSION",
    [4] = "SYSTEM_RESOURCE",
    [5] = "EMERGENCY_ACTIVATION",
    [6] = "EMERGENCY_DEACTIVATION",
    [7] = "DIFFERENCE_REPORT",
    [8] = "INVALID_PARAMETER",
    [9] = "THREAT",
    [10] = "HANDOVER",
    [11] = "GO_TO_VOICE",
    [12] = "CORRELATION",
}

-- Parse OMNI AlertEvent message (field 37)
local function parse_omni_alert_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.alert, buffer:range(0, length))

    -- Field 1: Message
    local message = pb.get_string(fields, 1)
    if message ~= "" then subtree:add(omni.fields.alert_message, message) end

    -- Field 2: Category
    if fields[2] then
        local cat = pb.get_field(fields, 2, 0)
        local cat_name = alert_category_values[cat] or tostring(cat)
        subtree:add(omni.fields.alert_category, cat_name)
    end

    -- Field 3: State
    if fields[3] then
        local state = pb.get_field(fields, 3, 0)
        local state_name = alert_state_values[state] or tostring(state)
        subtree:add(omni.fields.alert_state, state_name)
    end

    -- Field 6: Alert Type
    if fields[6] then
        local atype = pb.get_field(fields, 6, 0)
        local type_name = alert_type_values[atype] or tostring(atype)
        subtree:add(omni.fields.alert_type, type_name)
    end

    subtree:append_text(string.format(": %s", message ~= "" and message or "Alert"))
    return message
end

-- Parse OMNI FlightPathEvent message (field 42)
local function parse_omni_flight_path_event(buffer, length, tree)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.flight_path, buffer:range(0, length))

    -- Field 1: Sequence number (wrapper)
    if fields[1] then
        local data = fields[1].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("SeqNum"), 0, data:len())
            local seq = pb.get_field(wrapper, 1, 0)
            if type(seq) == "number" then
                subtree:add(omni.fields.flight_path_seq, seq)
            end
        end
    end

    -- Field 4: Total points (wrapper)
    if fields[4] then
        local data = fields[4].values[1]
        if data and type(data) ~= "number" then
            local wrapper = pb.parse_message(data:tvb("TotalPts"), 0, data:len())
            local pts = pb.get_field(wrapper, 1, 0)
            if type(pts) == "number" then
                subtree:add(omni.fields.flight_path_points, pts)
            end
        end
    end

    subtree:append_text(": Flight Path")
    return "FlightPath"
end

-- Determine OMNI event type name from oneof field number
local omni_event_types = {
    [11] = "Other",
    [12] = "Track",
    [13] = "Player",
    [14] = "Sensor",
    [15] = "Shape",
    [16] = "Chat",
    [17] = "MissionAssignment",
    [20] = "Weather",
    [22] = "AirfieldStatus",
    [23] = "PersonnelRecovery",
    [25] = "EntityManagement",
    [26] = "NetworkManagement",
    [29] = "NavigationVector",
    [36] = "Image",
    [37] = "Alert",
    [42] = "FlightPath",
}

-- Parse OMNI BaseEvent message (field numbers from baseevent.proto)
local function parse_omni_base_event(buffer, length, tree, pinfo)
    local fields = pb.parse_message(buffer, 0, length)
    local subtree = tree:add(omni.fields.base_event, buffer:range(0, length))

    if not subtree or type(subtree) ~= "userdata" then
        return
    end

    -- Field 1: entity_id (uint64)
    local entity_id = pb.get_field(fields, 1, 0)
    -- Field 9: event_sequence_number (uint64)
    local seq_num = pb.get_field(fields, 9, 0)

    -- Add entity_id and seq_num as strings to handle large uint64 values
    if entity_id ~= 0 then
        subtree:add(omni.fields.entity_id, tostring(entity_id))
    end
    if seq_num ~= 0 then
        subtree:add(omni.fields.seq_num, tostring(seq_num))
    end

    -- Field 2: EventOrigin
    if fields[2] then
        local data = fields[2].values[1]
        if data and type(data) ~= "number" then
            parse_omni_origin(data:tvb("Origin"), data:len(), subtree)
        end
    end

    -- Field 4: TimeOfValidity
    if fields[4] then
        local data = fields[4].values[1]
        if data and type(data) ~= "number" then
            parse_omni_time(data:tvb("Time"), data:len(), subtree)
        end
    end

    -- Field 5: Aliases (repeated)
    if fields[5] then
        for _, alias_data in ipairs(fields[5].values) do
            if alias_data and type(alias_data) ~= "number" then
                parse_omni_alias(alias_data:tvb("Alias"), alias_data:len(), subtree)
            end
        end
    end

    -- Parse oneof MessageEvent (fields 11-42)
    local event_type = "Unknown"
    local event_info = ""

    for field_num, type_name in pairs(omni_event_types) do
        if fields[field_num] then
            event_type = type_name
            local data = fields[field_num].values[1]
            if data and type(data) ~= "number" then
                if field_num == 12 then
                    event_info = parse_omni_track_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 13 then
                    event_info = parse_omni_player_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 14 then
                    event_info = parse_omni_sensor_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 15 then
                    event_info = parse_omni_shape_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 16 then
                    event_info = parse_omni_chat_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 17 then
                    event_info = parse_omni_mission_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 20 then
                    event_info = parse_omni_weather_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 22 then
                    event_info = parse_omni_airfield_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 23 then
                    event_info = parse_omni_pr_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 25 then
                    event_info = parse_omni_entity_mgmt_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 26 then
                    event_info = parse_omni_network_mgmt_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 29 then
                    event_info = parse_omni_nav_vector_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 36 then
                    event_info = parse_omni_image_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 37 then
                    event_info = parse_omni_alert_event(data:tvb(type_name), data:len(), subtree)
                elseif field_num == 42 then
                    event_info = parse_omni_flight_path_event(data:tvb(type_name), data:len(), subtree)
                else
                    -- Generic handling for other event types
                    local evt_tree = subtree:add(omni.fields.event_type, type_name)
                    evt_tree:set_text(string.format("%s Event", type_name))
                end
            end
            break
        end
    end

    subtree:add(omni.fields.event_type, event_type)
    subtree:append_text(string.format(": %s (Entity %d)", event_type, entity_id))

    pinfo.cols.info:append(string.format(" [%s #%d]", event_type, entity_id))
end

--------------------------------------------------------------------------------
-- Main Dissector
--------------------------------------------------------------------------------

omni.dissector = function(buffer, pinfo, tree)
    local length = buffer:reported_length_remaining()
    local subtree = tree:add(omni, buffer:range(0, length), "OMNI Message")

    pinfo.cols.protocol:set(omni.name)
    pinfo.cols.info:set("OMNI")

    -- OMNI protobuf detection (starts with field tag, not magic byte)
    -- BaseEvent fields: 1=entity_id(string), 2=sequence_number(uint32), etc.
    -- Tags: 0x0A=field1/string, 0x10=field2/varint, 0x12=field2/string, etc.
    local first_byte = buffer:range(0, 1):uint()
    if first_byte == 0x0A or first_byte == 0x08 or first_byte == 0x10 or first_byte == 0x12 or
       first_byte == 0x1a or first_byte == 0x22 or first_byte == 0x2a or first_byte == 0x32 then
        -- Likely OMNI protobuf
        subtree:add(omni.fields.version, 0)
        subtree:add(omni.fields.length, length)
        subtree:add(omni.fields.protocol, "omni")
        subtree:append_text(string.format(", Version: 0, Length: %d, Protocol: omni", length))

        parse_omni_base_event(buffer, length, subtree, pinfo)
        return length
    end

    -- Unknown format
    subtree:add_proto_expert_info(omni.experts.unsupported, "Unknown message format")
    return 0
end

--------------------------------------------------------------------------------
-- Preference Change Handler
--------------------------------------------------------------------------------

omni.prefs_changed = function()
    -- Update OMNI port registration
    if default_settings.port ~= omni.prefs.port then
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):remove(default_settings.port, omni)
            DissectorTable.get("udp.port"):remove(default_settings.port, omni)
            -- QUIC support (if available in this Wireshark version)
            pcall(function()
                DissectorTable.get("quic.port"):remove(default_settings.port, omni)
            end)
        end
        default_settings.port = omni.prefs.port
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):add(default_settings.port, omni)
            DissectorTable.get("udp.port"):add(default_settings.port, omni)
            -- QUIC support (if available in this Wireshark version)
            pcall(function()
                DissectorTable.get("quic.port"):add(default_settings.port, omni)
            end)
        end
    end
end

--------------------------------------------------------------------------------
-- Register Dissector
--------------------------------------------------------------------------------

-- Register for TCP, UDP (includes multicast), and QUIC
DissectorTable.get("tcp.port"):add(default_settings.port, omni)
DissectorTable.get("udp.port"):add(default_settings.port, omni)

-- QUIC support (if available in this Wireshark version)
pcall(function()
    DissectorTable.get("quic.port"):add(default_settings.port, omni)
end)
