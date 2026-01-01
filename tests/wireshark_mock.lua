-- Wireshark API Mock for Testing
-- This module provides stub implementations of Wireshark APIs
-- allowing tak.lua to be loaded and tested outside of Wireshark

--------------------------------------------------------------------------------
-- Bit Operations Compatibility (for Lua 5.3+/5.4)
--------------------------------------------------------------------------------
-- Wireshark's Lua uses the 'bit' library, but Lua 5.3+ has native bit operators

bit = bit or {}

function bit.band(a, b)
    return a & b
end

function bit.bor(a, b)
    return a | b
end

function bit.bxor(a, b)
    return a ~ b
end

function bit.bnot(a)
    return ~a
end

function bit.lshift(a, n)
    return a << n
end

function bit.rshift(a, n)
    return a >> n
end

function bit.arshift(a, n)
    -- Arithmetic right shift
    if a >= 0 then
        return a >> n
    else
        return ~((~a) >> n)
    end
end

--------------------------------------------------------------------------------
-- TvbRange Mock - represents a range within a buffer
--------------------------------------------------------------------------------

local TvbRange = {}
TvbRange.__index = TvbRange

function TvbRange.new(data, offset, length)
    local self = setmetatable({}, TvbRange)
    self._data = data
    self._offset = offset
    self._length = length
    return self
end

function TvbRange:len()
    return self._length
end

function TvbRange:uint()
    -- Return unsigned integer (big-endian, 1-4 bytes)
    local result = 0
    for i = 0, self._length - 1 do
        result = result * 256 + self._data:byte(self._offset + i + 1)
    end
    return result
end

function TvbRange:le_uint()
    -- Return unsigned integer (little-endian, 1-4 bytes)
    local result = 0
    for i = self._length - 1, 0, -1 do
        result = result * 256 + self._data:byte(self._offset + i + 1)
    end
    return result
end

function TvbRange:le_uint64()
    -- Return unsigned 64-bit integer (little-endian)
    -- Note: Lua numbers may lose precision for large values
    local result = 0
    local multiplier = 1
    for i = 0, 7 do
        if self._offset + i + 1 <= #self._data then
            result = result + self._data:byte(self._offset + i + 1) * multiplier
            multiplier = multiplier * 256
        end
    end
    return result
end

function TvbRange:le_float()
    -- Return little-endian float/double
    if self._length == 4 then
        -- 32-bit float
        local bytes = {}
        for i = 0, 3 do
            bytes[i + 1] = self._data:byte(self._offset + i + 1) or 0
        end
        -- IEEE 754 single precision decode
        local b1, b2, b3, b4 = bytes[1], bytes[2], bytes[3], bytes[4]
        local sign = (b4 >= 128) and -1 or 1
        local exponent = (b4 % 128) * 2 + math.floor(b3 / 128)
        local mantissa = ((b3 % 128) * 256 + b2) * 256 + b1
        if exponent == 0 then
            return sign * mantissa * 2^(-149)
        elseif exponent == 255 then
            return mantissa == 0 and sign * math.huge or 0/0
        end
        return sign * (1 + mantissa * 2^(-23)) * 2^(exponent - 127)
    else
        -- 64-bit double
        local bytes = {}
        for i = 0, 7 do
            bytes[i + 1] = self._data:byte(self._offset + i + 1) or 0
        end
        -- IEEE 754 double precision decode
        local b1, b2, b3, b4, b5, b6, b7, b8 =
            bytes[1], bytes[2], bytes[3], bytes[4],
            bytes[5], bytes[6], bytes[7], bytes[8]
        local sign = (b8 >= 128) and -1 or 1
        local exponent = (b8 % 128) * 16 + math.floor(b7 / 16)
        local mantissa = ((((((b7 % 16) * 256 + b6) * 256 + b5) * 256 + b4) * 256 + b3) * 256 + b2) * 256 + b1
        if exponent == 0 then
            return sign * mantissa * 2^(-1074)
        elseif exponent == 2047 then
            return mantissa == 0 and sign * math.huge or 0/0
        end
        return sign * (1 + mantissa * 2^(-52)) * 2^(exponent - 1023)
    end
end

function TvbRange:string()
    -- Return as string
    return self._data:sub(self._offset + 1, self._offset + self._length)
end

function TvbRange:bytes()
    -- Return raw bytes
    return self._data:sub(self._offset + 1, self._offset + self._length)
end

function TvbRange:range(offset, length)
    -- Return a sub-range
    return TvbRange.new(self._data, self._offset + offset, length)
end

--------------------------------------------------------------------------------
-- Tvb Mock - represents a packet buffer
--------------------------------------------------------------------------------

local Tvb = {}
Tvb.__index = Tvb

function Tvb.new(data)
    local self = setmetatable({}, Tvb)
    if type(data) == "table" then
        -- Convert byte array to string
        local chars = {}
        for i, b in ipairs(data) do
            chars[i] = string.char(b)
        end
        self._data = table.concat(chars)
    else
        self._data = data
    end
    return self
end

function Tvb:len()
    return #self._data
end

function Tvb:range(offset, length)
    length = length or (#self._data - offset)
    return TvbRange.new(self._data, offset, length)
end

function Tvb:raw(offset, length)
    offset = offset or 0
    length = length or (#self._data - offset)
    return self._data:sub(offset + 1, offset + length)
end

--------------------------------------------------------------------------------
-- ByteArray Mock
--------------------------------------------------------------------------------

local ByteArray = {}
ByteArray.__index = ByteArray

function ByteArray.new(hex_or_data)
    local self = setmetatable({}, ByteArray)
    if type(hex_or_data) == "string" and hex_or_data:match("^[0-9a-fA-F]+$") then
        -- Hex string
        self._data = ""
        for i = 1, #hex_or_data, 2 do
            local byte = tonumber(hex_or_data:sub(i, i + 1), 16)
            self._data = self._data .. string.char(byte)
        end
    else
        self._data = hex_or_data or ""
    end
    return self
end

function ByteArray:tvb(name)
    return Tvb.new(self._data)
end

function ByteArray:len()
    return #self._data
end

--------------------------------------------------------------------------------
-- ProtoField Mock
--------------------------------------------------------------------------------

local ProtoField = {}

function ProtoField.string(abbr, name, desc)
    return {type = "string", abbr = abbr, name = name, desc = desc}
end

function ProtoField.uint8(abbr, name, base, valuestring, mask, desc)
    return {type = "uint8", abbr = abbr, name = name, base = base}
end

function ProtoField.uint16(abbr, name, base, valuestring, mask, desc)
    return {type = "uint16", abbr = abbr, name = name, base = base}
end

function ProtoField.uint32(abbr, name, base, valuestring, mask, desc)
    return {type = "uint32", abbr = abbr, name = name, base = base}
end

function ProtoField.uint64(abbr, name, base, valuestring, mask, desc)
    return {type = "uint64", abbr = abbr, name = name, base = base}
end

function ProtoField.double(abbr, name, desc)
    return {type = "double", abbr = abbr, name = name, desc = desc}
end

function ProtoField.bytes(abbr, name, desc)
    return {type = "bytes", abbr = abbr, name = name, desc = desc}
end

function ProtoField.none(abbr, name, desc)
    return {type = "none", abbr = abbr, name = name, desc = desc}
end

--------------------------------------------------------------------------------
-- Pref Mock (Preferences)
--------------------------------------------------------------------------------

local Pref = {}

function Pref.uint(label, default, desc)
    return {type = "uint", label = label, default = default, desc = desc, value = default}
end

function Pref.string(label, default, desc)
    return {type = "string", label = label, default = default, desc = desc, value = default}
end

function Pref.bool(label, default, desc)
    return {type = "bool", label = label, default = default, desc = desc, value = default}
end

function Pref.enum(label, default, desc, enum_table, radio)
    return {type = "enum", label = label, default = default, desc = desc, value = default}
end

--------------------------------------------------------------------------------
-- ProtoExpert Mock
--------------------------------------------------------------------------------

local ProtoExpert = {}

function ProtoExpert.new(abbr, text, group, severity)
    return {abbr = abbr, text = text, group = group, severity = severity}
end

--------------------------------------------------------------------------------
-- TreeItem Mock
--------------------------------------------------------------------------------

local TreeItem = {}
TreeItem.__index = TreeItem

function TreeItem.new()
    local self = setmetatable({}, TreeItem)
    self.children = {}
    self.text = ""
    return self
end

function TreeItem:add(field_or_proto, tvbrange, value, ...)
    local child = TreeItem.new()
    child.field = field_or_proto
    child.value = value
    table.insert(self.children, child)
    return child
end

function TreeItem:add_proto_expert_info(expert, text)
    -- Mock expert info
end

function TreeItem:set_text(text)
    self.text = text
end

function TreeItem:append_text(text)
    self.text = self.text .. text
end

--------------------------------------------------------------------------------
-- Pinfo Mock
--------------------------------------------------------------------------------

local Pinfo = {}
Pinfo.__index = Pinfo

function Pinfo.new()
    local self = setmetatable({}, Pinfo)
    self.cols = {
        protocol = "",
        info = ""
    }
    -- Make cols.info support :set() and :append()
    setmetatable(self.cols, {
        __index = function(t, k)
            if k == "info" or k == "protocol" then
                return setmetatable({_value = ""}, {
                    __tostring = function(s) return s._value end,
                    __index = {
                        set = function(s, v) s._value = v end,
                        append = function(s, v) s._value = s._value .. v end
                    }
                })
            end
            return rawget(t, k)
        end
    })
    return self
end

--------------------------------------------------------------------------------
-- Proto Mock
--------------------------------------------------------------------------------

local Proto = {}

function Proto.__call(self, abbr, name)
    local proto = {
        name = name,
        abbr = abbr,
        fields = {},
        experts = {},
        prefs = {
            port = 6969,
            omni_port = 8089
        },
        dissector = nil
    }
    return proto
end

setmetatable(Proto, Proto)

--------------------------------------------------------------------------------
-- DissectorTable Mock
--------------------------------------------------------------------------------

local DissectorTable = {}
local dissector_tables = {}

function DissectorTable.get(name)
    if not dissector_tables[name] then
        dissector_tables[name] = {
            _entries = {},
            add = function(self, port, dissector)
                self._entries[port] = dissector
            end
        }
    end
    return dissector_tables[name]
end

--------------------------------------------------------------------------------
-- Expert group/severity mocks
--------------------------------------------------------------------------------

expert = {
    group = {
        MALFORMED = "MALFORMED",
        UNDECODED = "UNDECODED",
        PROTOCOL = "PROTOCOL"
    },
    severity = {
        ERROR = "ERROR",
        WARN = "WARN",
        NOTE = "NOTE"
    }
}

--------------------------------------------------------------------------------
-- Base module mock
--------------------------------------------------------------------------------

base = {
    DEC = 10,
    HEX = 16
}

--------------------------------------------------------------------------------
-- Global functions
--------------------------------------------------------------------------------

function set_plugin_info(info)
    _G._plugin_info = info
end

--------------------------------------------------------------------------------
-- Export mocks to global scope
--------------------------------------------------------------------------------

_G.Tvb = Tvb
_G.TvbRange = TvbRange
_G.ByteArray = ByteArray
_G.ProtoField = ProtoField
_G.ProtoExpert = ProtoExpert
_G.Proto = Proto
_G.DissectorTable = DissectorTable
_G.TreeItem = TreeItem
_G.Pinfo = Pinfo
_G.Pref = Pref
_G.expert = expert
_G.base = base

-- Return module for require
return {
    Tvb = Tvb,
    TvbRange = TvbRange,
    ByteArray = ByteArray,
    ProtoField = ProtoField,
    ProtoExpert = ProtoExpert,
    Proto = Proto,
    DissectorTable = DissectorTable,
    TreeItem = TreeItem,
    Pinfo = Pinfo,
    Pref = Pref
}
