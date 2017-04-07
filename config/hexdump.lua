--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display a summary and
-- hexdump of all observed data.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- The table should contain functions.

-- Local function, does a hexdump.
local hexdump =  function(buf)
  for i=1, math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then io.write(string.format('  %08X  ', i-1)) end
    io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
    if i %  8 == 0 then io.write(' ') end
    if i % 16 == 0 then
      local s = buf:sub(i-16+1, i)
      for j = 1, #s do
        if s:byte(j) >= 32 and s:byte(j) <= 126 then
          io.write(s:sub(j,j))
  	else
	  io.write(".")
	end
      end
      io.write('\n')
    end
  end
end


-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

-- Used to recurse up the protocol stack and get protocol addresses as a
-- string.  context=protocol context, is_src=true to study source addresses,
-- otherwise it returns destination address stack.
observer.describe_address = function(context, is_src)
  local par = context:get_parent()
  local str = ""
  if par then
    if is_src then
      str = observer.describe_address(par, true)
    else
      str = observer.describe_address(par, false)
    end
  end
  local cls, addr
  if is_src then
    cls, addr = context:get_src_addr()
  else
    cls, addr = context:get_dest_addr()
  end
  if not(addr == "") then
    if not(str == "") then
      str = str .. ":"
    end
    str = str .. addr
  end
  return str
end

-- Puts out a one-line description of the event.  Parameter action is a
-- description of the event.
observer.describe = function(context, action)
  local liid = context:get_liid()
  local s = observer.describe_address(context, true)
  local d = observer.describe_address(context, false)
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
  hexdump(data)
  io.write("\n")
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local a = string.format("Stream data (size is %d)", #data)
  observer.describe(context, a)
  hexdump(data)
  io.write("\n")
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, icmp_type, icmp_code, data)
  local a = string.format("ICMP (type %d, code %d)", icmp_type, icmp_code)
  observer.describe(context, a)
  hexdump(data)
  io.write("\n")
end

-- This function is called when an IMAP message is observed.
observer.imap = function(context, data)
  local a = string.format("IMAP (size is %d)", #data)
  observer.describe(context, a)
  hexdump(data)
  io.write("\n")
end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(context, data)
  local a = string.format("IMAP SSL (size is %d)", #data)
  observer.describe(context, a)
  hexdump(data)
  io.write("\n")
end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(context, data)
  local a = string.format("POP3 (size is %d)", #data)
  observer.describe(context, a)
  hexdump(data)
  io.write("\n")
end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(context, data)
  local a = string.format("POP3 SSL (size is %d)", #data)
  observer.describe(context, a)
  hexdump(data)
  io.write("\n")
end

-- This function is called when a SIP request message is observed.
observer.sip_request = function(context, method, from, to, data)
  local a = string.format("SIP %s request", method)
  observer.describe(context, a)
  io.write(string.format("    From: %s\n", from))
  io.write(string.format("    To: %s\n", to))
  hexdump(body)
  io.write("\n")
end

-- This function is called when a SIP response message is observed.
observer.sip_response = function(context, code, status, from, to, data)
  local a = string.format("SIP response %s %s", code, status)
  observer.describe(context, a)
  io.write(string.format("    From: %s\n", from))
  io.write(string.format("    To: %s\n", to))
  hexdump(body)
  io.write("\n")
end

-- This function is called when a SIP SSL message is observed.
observer.sip_ssl = function(context, data)
 local a = string.format("SIP SSL (size is %d)", #data)
  observer.describe(context, a)
  hexdump(data)
  io.write("\n")
end

-- This function is called when an SMTP Authentication message is observed.
observer.smtp_auth = function(context, data)
  local a = string.format("SMTP Authentication (size is %d)", #data)
  observer.describe(context, a)
  hexdump(data)
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

  hexdump(body)

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

  hexdump(body)

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
  hexdump(data)
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

