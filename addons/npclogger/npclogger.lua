require 'luau'
require 'strings'
res = require('resources')
packets = require('packets')
pack = require('pack')
bit = require 'bit'

my_name = windower.ffxi.get_player().name

files = require('files')
file = T{}
file.compare = files.new('data/'.. my_name ..'/logs/comparison.log', true)

_addon.name = 'NPC Logger'
_addon.version = '0.2'
_addon.author = 'ibm2431'
_addon.commands = {'npclogger'}

logged_npcs = {}
seen_names = S{}
npc_info = {}
npc_names = {}
npc_raw_names = {}
npc_looks = {}
widescan_by_index = {}
widescan_info = {}
npc_ids_by_index = {}

loaded_sql_npcs = {}
loaded_table_npcs = {}
ordered_sql_ids = {}
num_sql_npcs = 0;
id_moved_keys = {} -- Based off captured Lua table

new_npcs = {}
        
basic_npc_info = {}
seen_masks = {
  [0x57] = {},
  [0x07] = {},
  [0x0F] = {}
}



-- =================================================
-- ==    Packet Formatting Functions              ==
-- == Shamelessly stolen from Arcon's PacketViwer ==
-- =================================================
string.hexformat_file = (function()
    -- Precompute hex string tables for lookups, instead of constant computation.
    local top_row = '        |  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      | 0123456789ABCDEF\n    ' .. '-':rep((16+1)*3 + 2) .. '  ' .. '-':rep(16 + 6) .. '\n'

    local chars = {}
    for i = 0x00, 0xFF do
        if i >= 0x20 and i < 0x7F then
            chars[i] = i:char()
        else
            chars[i] = '.'
        end
    end
    chars[0x5C] = '\\\\'

    local line_replace = {}
    for i = 0x01, 0x10 do
        line_replace[i] = '    %%%%3X |' .. ' %.2X':rep(i) .. ' --':rep(0x10 - i) .. '  %%%%3X | ' .. '%%s\n'
    end
    local short_replace = {}
    for i = 0x01, 0x10 do
        short_replace[i] = '%s':rep(i) .. '-':rep(0x10 - i)
    end

    -- Receives a byte string and returns a table-formatted string with 16 columns.
    return function(str, byte_colors)
        local length = #str
        local str_table = {}
        local from = 1
        local to = 16
        for i = 0, ((length - 1)/0x10):floor() do
            local partial_str = {str:byte(from, to)}
            local char_table = {
                [0x01] = chars[partial_str[0x01]],
                [0x02] = chars[partial_str[0x02]],
                [0x03] = chars[partial_str[0x03]],
                [0x04] = chars[partial_str[0x04]],
                [0x05] = chars[partial_str[0x05]],
                [0x06] = chars[partial_str[0x06]],
                [0x07] = chars[partial_str[0x07]],
                [0x08] = chars[partial_str[0x08]],
                [0x09] = chars[partial_str[0x09]],
                [0x0A] = chars[partial_str[0x0A]],
                [0x0B] = chars[partial_str[0x0B]],
                [0x0C] = chars[partial_str[0x0C]],
                [0x0D] = chars[partial_str[0x0D]],
                [0x0E] = chars[partial_str[0x0E]],
                [0x0F] = chars[partial_str[0x0F]],
                [0x10] = chars[partial_str[0x10]],
            }
            local bytes = (length - from + 1):min(16)
            str_table[i + 1] = line_replace[bytes]
                :format(unpack(partial_str))
                :format(short_replace[bytes]:format(unpack(char_table)))
                :format(i, i)
            from = to + 1
            to = to + 0x10
        end
        return '%s%s':format(top_row, table.concat(str_table))
    end
end)()

-- ======================
-- == Helper Functions ==
-- ======================

-- Converts a string in base base to a number.
--------------------------------------------------
function string.todec(numstr, base)
    -- Create a table of allowed values according to base and how much each is worth.
    local digits = {}
    local val = 0
    for c in ('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):gmatch('.') do
        digits[c] = val
        val = val + 1
        if val == base then
            break
        end
    end

    local index = base^(#numstr-1)
    local acc = 0
    for c in numstr:gmatch('.') do
        acc = acc + digits[c]*index
        index = index/base
    end

    return acc
end

-- Converts a byte string to a proper integer keeping endianness into account
--------------------------------------------------
function byte_string_to_int(x)
  x = string.todec(x, 16)
  x = bit.bswap(x)
  return x
end

-- =======================
-- == Logging Functions ==
-- =======================

-- Gets an NPC's name and stores it in a table
--------------------------------------------------
function get_npc_name(npc_id)
  local mob = false;
  local npc_name = '';
  mob = windower.ffxi.get_mob_by_id(npc_id);
  
  if (mob) then
    if (mob.name ~= '') then
      npc_names[npc_id] = string.gsub(mob.name, "'", "\'");
      npc_ids_by_index[mob.index] = npc_id;
    else
      npc_names[npc_id] = false;
    end
  else
    npc_names[npc_id] = 'NO_MOB';
  end
end

-- Logs basic NPC information to a table
----------------------------------------------
function get_basic_npc_info(data)
  local name = '';
  local polutils_name = '';
  local model_type = false;
  local individual_npc_info = {};
  
  local packet = packets.parse('incoming', data);
  local npc_id = packet['NPC'];
  
  if (npc_raw_names[npc_id] and npc_names[npc_id]) then
    -- This is a named mob using a hard-set model.
    -- Example: A friendly goblin in town, or a door.
    npc_type = "Simple NPC";
    name = npc_raw_names[npc_id];
    name = string.gsub(name, "'", "_");
    polutils_name = npc_names[npc_id];
    polutils_name = string.gsub(polutils_name, "'", "\\'");
    polutils_name = string.gsub(polutils_name, "\"", "\\\"");
  end
  
  if (npc_names[npc_id]) then
    -- The server didn't send a raw name to us, but
    -- Windower succeeded in getting an NPC name from the client.
    if (not npc_raw_names[npc_id]) then
      -- This is a named NPC whose appearance could be replicated by
      -- players if they wore the same equipment as the NPC.
      -- Example: Arpevion, T.K.
      npc_type = "Equipped NPC";
      polutils_name = npc_names[npc_id];
      polutils_name = string.gsub(polutils_name, "'", "\\'");
      polutils_name = string.gsub(polutils_name, "\"", "\\\"");
      name = string.gsub(polutils_name, " ", "_");
      name = string.gsub(name, "'", "_");
    end
  elseif (not npc_raw_names[npc_id]) then
    -- We can't trust Windower's Model field, so we'll determine
    -- what kind of NPC this is by looking at the width of our
    -- own looks field for the NPC that we recorded previously.
    -- A fully-equipped-type model is 20 bytes, or 40 characters.
    if (string.len(npc_looks[npc_id]) == 40) then
      -- This is an NPC used strictly in a CS, but doesn't have
      -- its own special appearance like storyline NPCs, so
      -- its appearance is built via equipment.
      -- Example: Filler NPCs walking around town during a CS,
      -- or unnamed Royal Knights who guard the king.
      npc_type = 'CS NPC';
      name = 'csnpc';
      polutils_name = '     ';
    else
      -- This is a completely unnamed mob with a simple appearance.
      -- It's probably a decoration of some kind.
      -- Example: The special decorations in towns during festivals.
      npc_type = 'Decoration';
      name = 'blank';
      polutils_name = '     ';
    end
  end
  
  individual_npc_info["id"] = npc_id;
  individual_npc_info["name"] = name;
  individual_npc_info["polutils_name"] = polutils_name;
  individual_npc_info["npc_type"] = npc_type;
  individual_npc_info["index"] = packet['Index'];
  individual_npc_info["x"] = packet['X'];
  individual_npc_info["y"] = packet['Z']; -- Windower and DSP have these axis swapped vs each other
  individual_npc_info["z"] = packet['Y'];
  individual_npc_info["r"] = packet['Rotation'];
  
  basic_npc_info[npc_id] = individual_npc_info;
  
  if (widescan_by_index[packet['Index']] and (not widescan_info[npc_id])) then
    widescan_info[npc_id] = widescan_by_index[packet['Index']];
    widescan_info[npc_id]['id'] = npc_id;
    write_widescan_info(npc_id);
  end
end

-- Returns a string of an NPC's basic info, to be printed when logging
----------------------------------------------
function basic_npc_info_string(npc_id)
  local npc_info = basic_npc_info[npc_id];
  return string.format(
    "NPC ID: %d\n  Name: %s\n  POLUtils_Name: %s\n  NPC Type: %s\n  XYZR: %.3f, %.3f, %.3f, %d\n",
    npc_info["id"],
    npc_info["name"],
    npc_info["polutils_name"],
    npc_info["npc_type"],
    npc_info["x"],
    npc_info["y"],
    npc_info["z"],
    npc_info["r"]
  )
end

-- Converts a hex string to a proper-endianned integer
--------------------------------------------------
function hex_data_to_int(hex_string)
  local from_hex_representation = tonumber(hex_string, 16);
  local byte_swapped = bit.bswap(from_hex_representation);
  return tonumber(byte_swapped, 10);
end

-- Builds string for raw logging
--------------------------------------------------
function log_raw(npc_id, mask, data)
  local info_string = basic_npc_info_string(npc_id);
  local hex_data = data:hexformat_file();
  local mask = string.lpad(mask:binary(), "0", 8);
  local log_string = '%s  Mask: %s\n%s\n':format(info_string, mask, hex_data);
  file.full:append(log_string);
end

-- Logs original packet data for an NPC into table
--------------------------------------------------
function log_packet_to_table(npc_id, npc_info, data)
  local log_string = '';
  
  log_string = log_string .. "    [".. tostring(npc_id) .."] = {";
  log_string = log_string .. string.format(
    "['id']=%d, ['name']=\"%s\", ['polutils_name']=\"%s\", ['npc_type']=\"%s\", ['index']=%d, ['x']=%.3f, ['y']=%.3f, ['z']=%.3f, ['r']=%d, ['flag']=%d, ['speed']=%d, ['speedsub']=%d, ['animation']=%d, ['animationsub']=%d, ['namevis']=%d, ['status']=%d, ['flags']=%d, ['name_prefix']=%d, ['look']=\"%s\", ",
    npc_info['id'],
    npc_info['name'],
    npc_info['polutils_name'],
    npc_info['npc_type'],
    npc_info['index'],
    npc_info['x'],
    npc_info['y'],
    npc_info['z'],
    npc_info['r'],
    npc_info['flag'],
    npc_info['speed'],
    npc_info['speedsub'],
    npc_info['animation'],
    npc_info['animationsub'],
    npc_info['namevis'],
    npc_info['status'],
    npc_info['flags'],
    npc_info['name_prefix'],
    npc_info['look']
  )
  log_string = log_string .. "['raw_packet']=\"".. data:hex() .."\"";
  log_string = log_string .. "},\n"
  file.packet_table:append(log_string);
end

-- Logs an NPC to memory, writes raw packet, and writes lua table
--------------------------------------------------
function log_npc(npc_id, mask, npc_info, data)
  local basic_info = basic_npc_info[npc_id];
  for k,v in pairs(basic_info) do
    npc_info[k] = v;
  end
  logged_npcs[npc_id] = npc_info
  log_raw(npc_id, mask, data);
  log_packet_to_table(npc_id, npc_info, data);
end

-- Reads an NPC SQL file and loads their values into a Lua table
--------------------------------------------------
function load_sql_into_table(zone)
  local id, name, polutils_name, r, x, y, z, flag, speed, speedsub, animation, animationsub, namevis, status, flags, look, name_prefix, required_expansion, widescan;
  local capture_string = "(%d+),(.*),(.*),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,']+),([^,']+),([^,']+),([^,]+),([^,']+),([^,]+),([^,]+)";
  
  local lines = files.readlines("data/".. my_name .."/current_sql/".. zone ..".sql")
  local loaded_npc = {}
  local num_loaded_npcs = 1
  
  for _,v in pairs(lines) do
    if (v) then
      v = string.gsub(v, ",'", ",");
      v = string.gsub(v, "',", ",");
      _, _, id, name, polutils_name, r, x, y, z, flag, speed, speedsub, animation, animationsub, namevis, status, flags, look, name_prefix, required_expansion, widescan = string.find(v, capture_string);
      loaded_npc = {}
      if (id) then
        loaded_npc['id'] = tonumber(id);
        loaded_npc['name'] = name;
        loaded_npc['polutils_name'] = polutils_name;
        loaded_npc['r'] = tonumber(r);
        loaded_npc['x'] = tonumber(x);
        loaded_npc['y'] = tonumber(y);
        loaded_npc['z'] = tonumber(z);
        loaded_npc['flag'] = tonumber(flag);
        loaded_npc['speed'] = speed;
        loaded_npc['speedsub'] = speedsub;
        loaded_npc['animation'] = tonumber(animation);
        loaded_npc['animationsub'] = tonumber(animationsub);
        loaded_npc['namevis'] = tonumber(namevis);
        loaded_npc['status'] = tonumber(status);
        loaded_npc['flags'] = tonumber(flags);
        loaded_npc['look'] = look;
        loaded_npc['name_prefix'] = tonumber(name_prefix);
        loaded_npc['widescan'] = widescan;
        loaded_npc['order'] = num_loaded_npcs;
        ordered_sql_ids[num_loaded_npcs] = tonumber(id);
        loaded_sql_npcs[tonumber(id)] = loaded_npc;
        num_loaded_npcs = num_loaded_npcs + 1;
      end
    end
  end
  num_sql_npcs = num_loaded_npcs;
end

-- Loads a table of NPC packets that NPC Logger logged itself.
--------------------------------------------------
function load_npc_packet_table(zone, into_main_table)
  local packet_table = require("data/".. my_name .."/tables/".. zone);
  packet_table = table.sort(packet_table);
  if (into_main_table) then
  
    for npc_id, npc_info in pairs(packet_table) do
      logged_npcs[npc_id] = npc_info;
      basic_npc_info[npc_id] = {}
      for field_name, field_value in pairs(npc_info) do
        basic_npc_info[npc_id][field_name] = field_value;
      end
      npc_looks[npc_id] = npc_info['look'];
      npc_raw_names[npc_id] = npc_info['name'];
      npc_names[npc_id] = npc_info['polutils_name'];
      seen_masks[0x07][npc_id] = true;
      seen_masks[0x0F][npc_id] = true;
      seen_masks[0x57][npc_id] = true;
      npc_ids_by_index[npc_info['index']] = npc_id;
    end
  else
    loaded_table_npcs = packet_table;
  end
end

-- Compares two NPC tables and returns false if there's no differences.
-- If there is a difference, will return the first one as a string.
--------------------------------------------------
function compare_npcs(sql_npc, npclogger_npc)
  local changed = false;
  local changes = '';
  local keys = {'polutils_name', 'x', 'y', 'z', 'animation', 'animationsub', 'status', 'flags', 'namevis', 'name_prefix', 'look'}
  -- A list of flags to avoid printing changes for if changing from one
  -- flag in the list to another in the list.
  local ignore_flags = S{1, 6, 7, 8, 14, 16, 21, 22, 29}
  for _,v in pairs(keys) do
    if (v == 'look') then
      npclogger_npc[v] = "0x".. string.rpad(npclogger_npc[v], "0", 40);
    end
    if (sql_npc[v] ~= npclogger_npc[v]) then
      changes = changes .. "'".. v .."': ".. sql_npc[v] .." changed to ".. npclogger_npc[v] .. " ";
      changed = true;
    end
  end
  if (sql_npc['flag'] ~= npclogger_npc['flag']) then
    if (changed) then
      changes = changes .. "'flag': ".. sql_npc['flag'] .." changed to ".. npclogger_npc['flag'] .. " ";
    elseif (not (ignore_flags[sql_npc['flag']] and ignore_flags[sql_npc['flag']])) then
      changes = changes .. "'flag': ".. sql_npc['flag'] .." changed to ".. npclogger_npc['flag'] .. " ";
      changed = true;
    end
  end
  if (changed) then
    if (sql_npc['r'] ~= npclogger_npc['r']) then
      changes = changes .. "'r': ".. sql_npc['r'] .." changed to ".. npclogger_npc['r'] .. " ";
    end
    return changes;
  else
    return changed;
  end
end

-- Compares two loaded NPC tables (from target SQL, and NPC Logger's table).
--------------------------------------------------
function compare_npc_tables(compress_id_start, compress_id_end)
  local npc_comparison = '';
  local moved_id_key = '';
  local sql_line = '';
  local k = 0;
  if (not (compress_id_start or compress_id_end)) then
    compress_id_start, compress_id_end = 0, 0
  end
  for i = 1, (num_sql_npcs - 1) do -- Force traversing in current SQL list order.
    k = ordered_sql_ids[i];
    v = loaded_sql_npcs[k];
    if (loaded_table_npcs[k]) then
      npc_comparison = compare_npcs(loaded_sql_npcs[k], loaded_table_npcs[k]);
      if (npc_comparison) then
        if (not ((v['id'] >= compress_id_start) and (v['id'] <= compress_id_end))) then
          file.compare:append("CHANGED: ".. k .."; ".. npc_comparison .."\n");
        end
        sql_line = make_sql_insert_string(loaded_table_npcs[k]);
        file.compare:append(sql_line .."\n");
      else
        -- print("VERIFIED: ".. k.."; ".. loaded_sql_npcs[k]['name']);
      end
    else
      file.compare:append("NOT FOUND: ".. k .."\n");
      --print("NOT FOUND: ".. k);
    end
  end
  file.compare:append("NEW NPCS: \n");
  -- Yes, we have to go through the new NPCs twice. The first time
  -- is to sort a list of keys, because Lua can't key sort.
  for k,v in pairs(loaded_table_npcs) do
    if (not loaded_sql_npcs[k]) then
      table.insert(new_npcs, k)
    end
  end
  table.sort(new_npcs)
  for _,v in pairs(new_npcs) do
    sql_line = make_sql_insert_string(loaded_table_npcs[v], true)
    file.compare:append(sql_line .."\n");
    --print("ADDED: ".. k .."; ".. loaded_table_npcs[k]['name']);
  end
end

-- Takes an NPC table and outputs and appropriate input statement
--------------------------------------------------
function make_sql_insert_string(npc, new_npc)
  if (new_npc) then
    npc["look"] = "0x".. string.rpad(npc["look"], "0", 40)
  end
  local sql_line = string.format(
    "INSERT INTO `npc_list` VALUES (%d,'%s','%s',%d,%.3f,%.3f,%.3f,%d,%d,%d,%d,%d,%d,%d,%d,%s,%d,%s,%d);",
    npc["id"],
    string.gsub(npc["name"], "'", "_"),
    string.gsub(npc["polutils_name"], "'", "\'"),
    npc["r"],
    npc["x"],
    npc["y"],
    npc["z"],
    npc["flag"],
    npc["speed"],
    npc["speedsub"],
    npc["animation"],
    npc["animationsub"],
    npc["namevis"],
    npc["status"],
    npc["flags"],
    npc["look"],
    npc["name_prefix"],
    'null',
    0
  )
  return sql_line;
end

-- Writes a mob's widescan info to a table log
--------------------------------------------------
function write_widescan_info(npc_id)
  local log_string = "    [".. tostring(npc_id) .."] = {";
  log_string = log_string .. string.format(
    "['id']=%d, ['name']=\"%s\", ['index']=%d, ['level']=%d",
    widescan_info[npc_id]['id'],
    widescan_info[npc_id]['name'],
    widescan_info[npc_id]['index'],
    widescan_info[npc_id]['level']
  )
  log_string = log_string .. "},\n"
  file.widescan:append(log_string);
end

-- Sets up tables and files for use in the current zone
--------------------------------------------------
function setup_zone(zone)
  local current_zone = res.zones[zone].en;
  file.packet_table = files.new('data/'.. my_name ..'/tables/'.. current_zone ..'.lua', true)
  file.full = files.new('data/'.. my_name ..'/logs/'.. current_zone ..'.log', true)
  file.widescan = files.new('data/'.. my_name ..'/widescan/'.. current_zone ..'.log', true)
  widescan_by_index = {}
  widescan_info = {}
  npc_ids_by_index = {}
end

function check_incoming_chunk(id, data, modified, injected, blocked)
  local packet = packets.parse('incoming', data)

  if (id == 0x00E) then
    local mask = packet['Mask'];
    if (seen_masks[mask] and (not seen_masks[mask][packet['NPC']])) then
      local npc_id = packet['NPC'];
      local npc_info = {}
      if ((packet['Name'] ~= '') and (not npc_raw_names[packet['NPC']]) and (not (mask == 0x57))) then
        -- Valid raw name we haven't seen yet is set.
        npc_raw_names[packet['NPC']] = packet['Name'];
      end
      if ((mask == 0x57) or (mask == 0x0F) or (mask == 0x07)) then
        windower.add_to_chat(7, "[NPC Logger] Logged NPC ID: " .. packet['NPC']);
        
        if (mask == 0x57) then
          -- Equipped model.
          npc_info['look'] = string.sub(data:hex(), (0x30*2)+1, (0x44*2));
        elseif ((mask == 0x0F) or (mask == 0x07)) then
          -- Basic/standard NPC model.
          npc_info['look'] = string.sub(data:hex(), (0x30*2)+1, (0x34*2));
        end
        npc_looks = npc_info['look'];
        
        npc_info['flag'] = byte_string_to_int(string.sub(data:hex(), (0x18*2)+1, (0x1C*2)));
        npc_info['speed'] = tonumber(string.sub(data:hex(), (0x1C*2)+1, (0x1D*2)), 16);
        npc_info['speedsub'] = tonumber(string.sub(data:hex(), (0x1D*2)+1, (0x1E*2)), 16);
        npc_info['animation'] = tonumber(string.sub(data:hex(), (0x1F*2)+1, (0x20*2)), 16);
        npc_info['animationsub'] = tonumber(string.sub(data:hex(), (0x2A*2)+1, (0x2B*2)), 16);
        npc_info['namevis'] = tonumber(string.sub(data:hex(), (0x2B*2)+1, (0x2C*2)), 16);
        npc_info['status'] = tonumber(string.sub(data:hex(), (0x20*2)+1, (0x21*2)), 16);
        npc_info['flags'] = byte_string_to_int(string.sub(data:hex(), (0x21*2)+1, (0x25*2)));
        npc_info['name_prefix'] = tonumber(string.sub(data:hex(), (0x27*2)+1, (0x28*2)), 16);
        
        if (not basic_npc_info[npc_id]) then
          -- Give the game a second or two to load the mob into memory before using Windower functions.
          coroutine.schedule(function() get_npc_name(npc_id) end, 2);
          coroutine.schedule(function() get_basic_npc_info(data) end, 2.2);
        end
        coroutine.schedule(function() log_npc(npc_id, packet['Mask'], npc_info, data) end, 3);
        seen_masks[mask][npc_id] = true;
      end
    end
  elseif (id == 0xF4) then
    local index, name, level = packet["Index"], packet["Name"], packet["Level"];
    if (not widescan_by_index[index]) then
      widescan_by_index[index] = {['index']=index,['name']=name,['level']=level};
      local npc_id = npc_ids_by_index[index];
      if (npc_id and (not widescan_info[npc_id])) then
        widescan_info[npc_id] = widescan_by_index[index];
        widescan_info[npc_id]['id'] = npc_id;
        write_widescan_info(npc_id);
      end
    end
  end
end

windower.register_event('zone change', function(new, old)
  setup_zone(new);
end)

setup_zone(windower.ffxi.get_info().zone)
windower.register_event('incoming chunk', check_incoming_chunk);

-- Edit/uncomment the next line to simply load a table into memory
-- (If you captured NPCs and just want to hop around and get widescan data)
--load_npc_packet_table("Abyssea - Attohwa", true);

-- Edit/uncomment the following three lines to compare a table to SQL
-- load_sql_into_table("Abyssea - Grauberg"); -- (npclogger/data/character/current sql/"zone".sql)
-- load_npc_packet_table("Abyssea - Grauberg"); -- (npclogger/data/character/tables/"zone".sql)
--compare_npc_tables(); -- Prints results to: npclogger/data/logs/comparison.log

-- Edit/uncomment the following line to "compress" SQL Insert changes for NPCs between
-- the two IDs (ie: don't show CHANGED: blah). Good for copy/pasting entire blocks.
-- compare_npc_tables(17818119, 17818197);