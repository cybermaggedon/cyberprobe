--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to emit alerts when it
-- notices big volumes going to an attacker.
-- 
-- This example is too simple - if the alert fails to deliver, it crashes out.
-- But, you get the point.
--
-- This makes use of LuaSocket, won't work if you don't have that installed.
--

local socket = require("socket")

local observer = {}

local volume = {}
local threshold = {}

observer.data = function(context, data)

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
    
    -- Send an alert
    local s = socket.connect("localhost", 10101)
    s:send(string.format("%s %s\n", dest, volume[dest]))
    s:close()

  end

end

observer.trigger = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

print("Configuration loaded")

return observer

