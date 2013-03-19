require ("bit")

-- create owfs protocol and its fields
p_owfs = Proto ("owfs","OWFS")

local f_version = ProtoField.uint32("owfs.version", "Version", base.HEX)
local f_payload = ProtoField.uint32("owfs.payload", "Payload len", base.HEX)
local f_type    = ProtoField.uint32("owfs.type", "Type", base.HEX)
local f_flags   = ProtoField.uint32("owfs.flags", "Flags", base.HEX)
local f_size    = ProtoField.uint32("owfs.size", "Size", base.HEX)
local f_offset  = ProtoField.uint32("owfs.offset", "Offset", base.HEX)
local f_data    = ProtoField.string("owfs.data", "Data", FT_STRING)

--local f_debug = ProtoField.uint8("owfs.debug", "Debug")
p_owfs.fields = {f_version, f_payload, f_type, f_flags, f_size, f_offset, f_data}

p_owfs.prefs["tcp_port"] = Pref.uint("TCP Port", 4304, "TCP Port for OWFS")

local msg_types = {
	[0]  = {"error", "Note used"},
	[1]  = {"nop", "No-Op (not used)"},
	[2]  = {"read", "Read from 1-wire bus"},
	[3]  = {"write", "Write to 1-wire bus"},
	[4]  = {"dir", "List 1-wire bus"},
	[5]  = {"size", "Get data size (not used)"},
	[6]  = {"present", "Is the specified component recognized and known"},
	[7]  = {"dirall", "List 1-wire bus, in one packet string"},
	[8]  = {"get",	"dirall or read depending on path"},
	[9]  = {"dirallslash", "dirall but with directory entries getting a trailing '/'"},
	[10] = {"getslash", "dirallslash or read depending on path"}
};

-- owfs dissector function
function p_owfs.dissector (buf, pinfo, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() < 24 then return end
  local version = buf(0,4):int()
  -- or not hasbit(version, bit(16))
  --if version ~= 0x0 then return end
  
  pinfo.cols.protocol = p_owfs.name

  -- create subtree for owfs
  subtree = root:add(p_owfs, buf(0))
  -- add protocol fields to subtree
  local len = buf(4,4):int()
  subtree:add(f_version, buf(0,4))
  subtree:add(f_payload, buf(4,4))
  
  -- Check msg type
  local type = subtree:add(f_type,    buf(8,4))
  if msg_types[buf(8,4):uint()] ~= nil then
	type:append_text(" (" .. msg_types[buf(8,4):uint()][1] .. ")")
  end
  
  -- Check flags
  local flags = buf(12,4):uint()
  local flags_s = {}
  if bit.band(flags, 0x002) > 0 then table.insert(flags_s, "BUS_RET") end
  if bit.band(flags, 0x004) > 0 then table.insert(flags_s, "PERSISTENT") end
  if bit.band(flags, 0x008) > 0 then table.insert(flags_s, "ALIAS") end
  if bit.band(flags, 0x010) > 0 then table.insert(flags_s, "SAFE_MODE") end
  if bit.band(flags, 0x020) > 0 then table.insert(flags_s, "UNCACHED") end
  if bit.band(flags, 0x100) > 0 then table.insert(flags_s, "REQUEST") end
  subtree:add(f_flags,   flags):append_text(" (" .. table.concat(flags_s, ", ") .. ")")
  
  subtree:add(f_size,    buf(16,4))
  subtree:add(f_offset,  buf(20,4))
  if len > 0 then
    if 24 + len > buf:len() then
        pinfo.desegment_len = len
    end
    subtree:add(f_data, buf(24,len))
    return 24 + len
  end
  
  return 24
end

-- Initialization routine
function p_owfs.init()
	local tcp_dissector_table = DissectorTable.get("tcp.port")

	tcp_dissector_table:add(p_owfs.prefs["tcp_port"], p_owfs)
end

