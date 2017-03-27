--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to watch data volumes being
-- transferred to identified attackers, and provide summary information about
-- volumes as they increase.
--
-- It alerts when volumes go over the 256k threshold and then doubles the
-- threshold for IP addresses.

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

local volume = {}
local threshold = {}

local track = function(context, size)

  trig = context:get_trigger_info()
  src, dest = context:get_network_info()
  if not(trig == dest) then
    return
  end

  if volume[dest] == nil then
    threshold[dest] = 256 * 1024
    volume[dest] = 0
  end

  volume[dest] = volume[dest] + size

  if volume[dest] > threshold[dest] then
    local vol = (volume[dest] / 1024 / 1024)
    io.write(string.format("%0.1f MB has flowed to address %s\n", vol, dest))
    threshold[dest] = threshold[dest] * 2
  end

end

-- The table should contain functions.

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(context)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  track(context, #data)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  track(context,#data)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  track(context,#data)
end

-- This function is called when an IMAP message is observed.
observer.imap = function(context, data)
  track(context,#data)
end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(context, data)
  track(context,#data)
end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(context, data)
  track(context,#data)
end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(context, data)
  track(context,#data)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  track(context,#body)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  track(context,#body)
end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)
end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)
  track(context,#data)
end

-- This function is called when a DNS over TCP message is observed.
observer.dns_over_tcp_message = function(context, header, queries, answers, auth, add)
end

-- This function is called when a DNS over UDP message is observed.
observer.dns_over_udp_message = function(context, header, queries, answers, auth, add)
end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
end

-- This function is called when an NTP timestamp message is observed.
observer.ntp_timestamp_message = function(context, hdr, info)
end

-- This function is called when an NTP control message is observed.
observer.ntp_control_message = function(context, hdr, info)
end

-- This function is called when an NTP private message is observed.
observer.ntp_private_message = function(context, hdr, info)
end


-- Return the table
return observer

