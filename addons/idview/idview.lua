require 'luau'
require 'strings'
res = require('resources')
packets = require('packets')
pack = require('pack')
bit = require 'bit'

_addon.name = 'IDView'
_addon.version = '0.1'
_addon.author = 'ibm2431'
_addon.commands = {'idview'}

my_name = windower.ffxi.get_player().name

files = require('files')
file = T{}
file.simple = files.new('data/'.. my_name ..'/logs/simple.log', true)
file.raw = files.new('data/'.. my_name ..'/logs/raw.log', true)

-- Prettily formats a packet. Shamelessly stolen from Arcon's Packet Viewer.
--------------------------------------------------
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
  x = string.todec(x, 16);
  x = bit.bswap(x);
  return x;
end

-- Pulls apart params sent with an event CS packet
--------------------------------------------------
function get_params(params_string)
  local params = {}
  local final_param_string = '';
  for i=0, 7 do
    params[i + 1] = string.sub(params_string, (i*4)+1, (i*4) + 4);
  end
  for _,v in ipairs(params) do
    final_param_string = final_param_string .. v .. ", ";
  end
  return final_param_string;
end

-- Sets up tables and files for use in the current zone
--------------------------------------------------
function setup_zone(zone)
  local current_zone = res.zones[zone].en;
  file.simple = files.new('data/'.. my_name ..'/simple/'.. current_zone ..'.log', true)
  file.raw = files.new('data/'.. my_name ..'/raw/'.. current_zone ..'.log', true)
end

-- Checks outgoing chunks for dialog choices and logs them
--------------------------------------------------
function check_outgoing_chunk(id, data, modified, injected, blocked)
  local update_packet = packets.parse('outgoing', data)
  local log_string = "";
  local mob;
  local mob_name;
  log_string = "Outgoing Packet: ";
  if (id == 0x05B) then
    -- Dialog Choice
    mob = windower.ffxi.get_mob_by_id(update_packet['Target']);
    if (mob) then mob_name = mob.name end;
    log_string = log_string .. '0x05B (Event Option), ';
    log_string = log_string .. 'NPC: ' .. update_packet['Target'];
    if (mob_name) then
      log_string = log_string .. ' ('.. mob.name ..')'
    end;
    log_string = log_string .. string.format(', Event: 0x%04X, ', update_packet['Menu ID']);
    raw_header = log_string;
    log_string = log_string .. 'Option: '.. update_packet['Option Index'];
  end
  
  if (log_string ~= "Outgoing Packet: ") then
    windower.add_to_chat(7, "[ID View] " .. log_string);
    file.simple:append(log_string .. "\n\n");
    file.raw:append(raw_header .. '\n'.. data:hexformat_file() .. '\n');
  end
end

-- Checks incoming chunks for event CSes or NPC chats and logs them
--------------------------------------------------
function check_incoming_chunk(id, data, modified, injected, blocked)
  local update_packet = packets.parse('incoming', data)
  local log_string = "";
  local raw_header = "";
  local mob;
  local mob_name;
  log_string = "Incoming Packet: ";
  if (id == 0x036) then
    -- NPC Chat
    log_string = log_string .. '0x036 (NPC Chat), ';
    log_string = log_string .. 'Actor: ' .. update_packet['Actor'];
    mob = windower.ffxi.get_mob_by_id(update_packet['Actor']);
    if (mob) then mob_name = mob.name end;
    if (mob_name) then log_string = log_string .. ' ('.. mob.name ..')' end;
    log_string = log_string .. ', Message: '.. update_packet['Message ID'];
  elseif ((id == 0x032) or (id == 0x034)) then
    -- Event CS
    if (id == 0x032) then
      log_string = log_string .. '0x032 (CS Event), ';
    else
      log_string = log_string .. '0x034 (CS Event + Params), ';
    end
    log_string = log_string .. 'NPC: ' .. update_packet['NPC'];
    mob = windower.ffxi.get_mob_by_id(update_packet['NPC']);
    if (mob) then mob_name = mob.name end;
    if (mob_name) then
      log_string = log_string .. ' ('.. mob.name ..')'
    end;
    log_string = log_string .. string.format(', Event: 0x%04X', update_packet['Menu ID']);
    raw_header = log_string;
    local params = get_params(string.sub(data:hex(), (0x08*2)+1, (0x28*2)));
    log_string = log_string .. string.format(', Params: %s', params);
  end
  
  if (log_string ~= "Incoming Packet: ") then
    windower.add_to_chat(7, "[ID View] " .. log_string);
    file.simple:append(log_string .. "\n\n");
    file.raw:append(raw_header .. '\n'.. data:hexformat_file() .. '\n');
  end
end

windower.register_event('zone change', function(new, old)
  setup_zone(new);
end)

windower.register_event('outgoing chunk', check_outgoing_chunk);
windower.register_event('incoming chunk', check_incoming_chunk);
setup_zone(windower.ffxi.get_info().zone)