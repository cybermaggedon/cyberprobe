--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file does nothing.  The event functions are all empty
-- stubs.  Maybe a good starting point for building your own config from
-- scratch.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

observer.event = function(e)

  if e.action ~= "connected_up" then
    return
  end

  net, src, dest = e.context:get_network_info()

  local cls, src_addr, dest_addr

  cls, src_addr = e.context:get_src_addr()
  cls, dest_addr = e.context:get_dest_addr()

  if not((src_addr == "22") or (dest_addr == "22")) then
    -- Ignore non-ssh traffic
    return
  end

  if src == "192.168.1.8" or dest == "192.168.1.8" then
    -- Ignore admin workstation
    return
  end
    
  print("Reset on ssh connection between " .. src .. " and " .. dest)
  e.context:forge_tcp_reset()

end

-- Return the table
return observer

