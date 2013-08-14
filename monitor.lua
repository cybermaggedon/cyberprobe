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

observer.volume = {}
observer.threshold = {}

observer.data = function(context, data)

  liid = cybermon.get_liid(context)
  src, dest = cybermon.get_network_info(context)

  if observer.volume[dest] == nil then
    observer.threshold[dest] = 256 * 1024
    observer.volume[dest] = 0
  end

  observer.volume[dest] = observer.volume[dest] + data:len()

  if observer.volume[dest] > observer.threshold[dest] then
    local vol = (observer.volume[dest] / 1024 / 1024)
    io.write(string.format("%0.1f MB has flowed to address %s\n", vol, dest))
    observer.threshold[dest] = observer.threshold[dest] * 2
  end

end

observer.trigger = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

print("Configuration loaded")

return observer

