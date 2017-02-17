--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display a summary of all
-- observered events.  This can serve as a template.
--

local addr = require("util.addresses")

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

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

-- Puts out a one-line description of the event.  Parameter action is a
-- description of the event.
observer.describe = function(context, action)
  local liid = context:get_liid()
  local s = addr.describe_address(context, true)
  local d = addr.describe_address(context, false)
  io.write(string.format("%s: %s -> %s. %s\n", liid, s, d, action))
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(context)
  --observer.describe(context, "Connected")
  --io.write("\n")
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  --observer.describe(context, "Disconnected")
  --io.write("\n")
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local a = string.format("Datagram (size is %d)", #data)
  observer.describe(context, a)
  io.write("\n")
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local a = string.format("Stream data (size is %d)", #data)
  observer.describe(context, a)
  io.write("\n")
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local a = string.format("ICMP (size is %d)", #data)
  observer.describe(context, a)
  io.write("\n")
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local a = string.format("HTTP %s request", method)
  observer.describe(context, a)
  io.write(string.format("    URL %s\n", url))

  -- Write header
  for key, value in pairs(header) do
    io.write(string.format("    %s: %s\n", key, value))
  end

  io.write("\n")

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)

  local a = string.format("HTTP response %s %s", code, status)
  observer.describe(context, a)
  io.write(string.format("    URL %s\n", url))

  local rev = context:get_reverse()

  -- Write header
  for key, value in pairs(header) do
    io.write(string.format("    %s: %s\n", key, value))
  end

  io.write("\n")

end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)
  local a = string.format("SMTP command %s", command)
  observer.describe(context, a)
  io.write("\n")
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)
  local a = string.format("SMTP response %d", status)
  observer.describe(context, a)
  for k, v in pairs(text) do
    io.write(string.format("    %s\n", v))
  end
  io.write("\n")
end

-- This function is called when an SMTP DATA body is observed.
observer.smtp_data = function(context, from, to, data)
  local a = string.format("SMTP data")
  observer.describe(context, a)
  io.write(string.format("    From: %s\n", from))
  for key, value in pairs(to) do
    io.write(string.format("    To: %s\n", value))
  end
  io.write("\n")
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)

  if header.qr == 0 then
    observer.describe(context, "DNS query")
  else
    observer.describe(context, "DNS response")
  end

  for key, value in pairs(queries) do
    io.write(string.format("    Query: %s\n", value.name))
  end
  
  for key, value in pairs(answers) do
    io.write(string.format("    Answer: %s", value.name))
    if value.rdaddress then
       io.write(string.format(" -> %s", value.rdaddress))
    end
    if value.rdname then
       io.write(string.format(" -> %s", value.rdname))
    end
    io.write("\n")
  end

  io.write("\n")

end

-- This function is called when a NTP Timestamp message is observed.
observer.ntp_timestamp_message = function(context, base, info)
  local a = string.format("NTP Timestamp")
  observer.describe(context, a);
  io.write(string.format("  Leap Indicator      -> %u\n", base.leap_indicator));
  io.write(string.format("  Version             -> %u\n", base.version));
  io.write(string.format("  Mode                -> %u\n", base.mode));
  io.write(string.format("  Stratum             -> %u\n", info.stratum));
  io.write(string.format("  Poll                -> %u\n", info.poll));
  io.write(string.format("  Precision           -> %.6f\n", info.precision));
  io.write(string.format("  Root Delay          -> %.6f\n", info.root_delay));
  io.write(string.format("  Root Dispersion     -> %.6f\n", info.root_dispersion));
  io.write(string.format("  Reference Id        -> %u\n", info.reference_id));
  io.write(string.format("  Reference Timestamp -> %.9f\n", info.reference_timestamp));
  io.write(string.format("  Originate Timestamp -> %.9f\n", info.originate_timestamp));
  io.write(string.format("  Receive Timestamp   -> %.9f\n", info.receive_timestamp));
  io.write(string.format("  Transmit Timestamp  -> %.9f\n", info.transmit_timestamp));
  if info.has_extension then
       io.write("  Extension           -> True\n");
  else
       io.write("  Extension           -> False\n");
  end
end

-- This function is called when a NTP Control message is observed.
observer.ntp_control_message = function(context, base)
  local a = string.format("NTP Control")
  observer.describe(context, a);
  io.write(string.format("  Leap Indicator      -> %u\n", base.leap_indicator));
  io.write(string.format("  Version             -> %u\n", base.version));
  io.write(string.format("  Mode                -> %u\n", base.mode));
end

-- This function is called when a NTP Private message is observed.
observer.ntp_private_message = function(context, base)
  local a = string.format("NTP Private")
  observer.describe(context, a);
  io.write(string.format("  Leap Indicator      -> %u\n", base.leap_indicator));
  io.write(string.format("  Version             -> %u\n", base.version));
  io.write(string.format("  Mode                -> %u\n", base.mode));
end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local a = string.format("FTP command %s", command)
  observer.describe(context, a)
  io.write("\n")
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local a = string.format("FTP response %d", status)
  observer.describe(context, a)
  for k, v in pairs(text) do
    io.write(string.format("    %s\n", v))
  end
  io.write("\n")
end

-- Return the table
return observer

