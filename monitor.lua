--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to watch data volumes being
-- transferred to identified attackers, and provide summary information about
-- volumes as they increase.
--
-- It alerts when volumes go over the 256k threshold and then doubles the
-- threshold for IP addresses.
--

local observer = {}

local volume = {}
local threshold = {}

observer.connection_data = function(context, data)

  liid = cybermon.get_liid(context)
  src, dest = cybermon.get_network_info(context)
  trig = cybermon.get_trigger_info(context)

  -- Ignore data which isn't going *to* the attacker.
  if not(trig == dest) then
    return
  end

  if volume[dest] == nil then
    threshold[dest] = 256 * 1024
    volume[dest] = 0
  end

  volume[dest] = volume[dest] + data:len()

  if volume[dest] > threshold[dest] then
    local vol = (volume[dest] / 1024 / 1024)
    io.write(string.format("%0.1f MB has flowed to address %s\n", vol, dest))
    threshold[dest] = threshold[dest] * 2
  end

end

observer.connection_up = function(context)
  liid = cybermon.get_liid(context)
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", cybermon.describe_src(context),
           cybermon.describe_dest(context)))
  io.write("  Connected.\n\n");
end

observer.connection_down = function(context)
  liid = cybermon.get_liid(context)
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", cybermon.describe_src(context),
           cybermon.describe_dest(context)))
  io.write("  Disconnected.\n\n");
end

observer.datagram = observer.connection_data

observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

print("Configuration loaded")

return observer

