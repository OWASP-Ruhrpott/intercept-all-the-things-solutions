-- You can find the plugin folder in wireshark Help->About Wireshark->Folders
-- This is stored under $HOME/.local/lib/wireshark/plugins/
-- You can reload the script with Ctrl+Shift+L in wireshark

-- This is from https://github.com/kikito/md5.lua and is in the same folder.
local md5 = require 'md5'

bl_protocol = Proto("BINLOG",  "Binary Login")
bl_port = 9999

-- Header fields
msg_type = ProtoField.string("binlog.type", "Type", base.ASCII)
tcp_length = ProtoField.int32 ("binlog.tcp_length", "Length", base.DEC)
msg_user = ProtoField.string("binlog.user", "User", base.ASCII)
msg_user_id = ProtoField.bytes("binlog.user", "User ID")
password = ProtoField.string("binlog.password", "Password", base.ASCII)
payload_length = ProtoField.int32 ("binlog.payload_length", "Length Payload", base.DEC)
payload = ProtoField.string("binlog.payload", "Payload", base.ASCII)
checksum = ProtoField.bytes("binlog.checksum", "MD5")
checksum_correct = ProtoField.string("binlog.checksum_correct", "Checksum", base.ASCII)

bl_protocol.fields = {
  -- Header
  msg_type, msg_user, msg_user_id, password, tcp_length, payload_length, payload, checksum, checksum_correct
}

function getUsernameById(id)
    if id == 0 then
      return "admin"
    elseif id == 1 then
      return "bob"
    elseif id == 2 then
      return "alice"
    else
      return "N/A"
    end
end

function bl_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    tcp_port_dst = tostring(pinfo.src_port)
    tcp_port_src = tostring(pinfo.dst_port)

    local subtree = tree:add(bl_protocol, buffer(), "Binary Login")

    if tostring(bl_port) == tcp_port_src then
      pinfo.cols.protocol = bl_protocol.name .. " CLIENT"
      if buffer(0,1):uint() == 0x42 then
        subtree:add(msg_type, "Username")
        subtree:add(msg_user, buffer(1))
        subtree:add(tcp_length, length)
        subtree:add(payload_length, length-1)
        pinfo.cols.info = "Get user id by username"
      elseif buffer(0,1):uint() == 0x01 then
        subtree:add(msg_type, "Login")
        subtree:add(tcp_length, buffer(1,1))
        subtree:add(payload_length, buffer(3,1))
        subtree:add(msg_user_id, buffer(5,2))
        subtree:add(msg_user, getUsernameById(buffer(5,2):uint()))
        subtree:add(password, buffer(7,buffer(3,1):uint()-1-2))
        subtree:add(checksum, buffer(5+buffer(3,1):uint(),16))
        if "" .. buffer(5+buffer(3,1):uint(),16) == "" .. md5.sumhexa(buffer(0,buffer(3,1):uint()+4):string()) then
          subtree:add(checksum_correct, "Verified")
        else
          subtree:add(checksum_correct, "Not Verified")
        end
        pinfo.cols.info = "Login with user id and password"
      else
        subtree:add(msg_type, "[UNKOWN]")
      end
    elseif tostring(bl_port) == tcp_port_dst then
      pinfo.cols.protocol = bl_protocol.name .. " SERVER"
      subtree:add(tcp_length, length)
      subtree:add(payload, buffer(0))
      pinfo.cols.info = "Response from Server"
    else
      pinfo.cols.protocol = bl_protocol.name .. " [UNKOWN]"
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(bl_port, bl_protocol)
