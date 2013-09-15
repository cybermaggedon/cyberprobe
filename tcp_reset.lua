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

-- The table should contain functions.

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(liid, addr)
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(liid)
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(context)

    src, dest = context:get_network_info()

    local cls, src_addr, dest_addr

    cls, src_addr = context:get_src_addr()
    cls, dest_addr = context:get_dest_addr()

    if not((src_addr == "22") or (dest_addr == "22")) then
      -- Ignore non-ssh traffic
      return
    end

    if src == "192.168.1.8" or dest == "192.168.1.8" then
      -- Ignore admin workstation
      return
    end

    
    print("Spike! on ssh connection between " .. src .. " and " .. dest)
    context:forge_tcp_reset()

end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)
end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)
end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
end

-- Return the table
return observer

