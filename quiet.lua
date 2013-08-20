--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display nothing.  Useful
-- for processing data to find a crash or something.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- The table should contain functions.  We currently use: data, trigger,
-- trigger_down.

-- This function is called when a data transfer occurs.  Context information
-- is contained in 'context', and 'data' is a string, containing the packet
-- data.
observer.connection_data = function(context, data)
end

observer.connection_up = function(context)
end

observer.connection_down = function(context)
end

observer.datagram = observer.connection_data

-- This function is called when the address of an attacker has been
-- identified.
observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

-- This function is called when a known attacker goes off the air
observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

observer.http_request = function(context, method, url, header, body)
end

observer.http_response = function(context, code, status, header, body)
end

-- Return the table
return observer

