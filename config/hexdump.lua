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
observer.trigger_up = function(e)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(e)
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
observer.describe = function(e, action)
  local liid = context:get_liid()
  local s = observer.describe_address(context, true)
  local d = observer.describe_address(context, false)
  io.write(string.format("%s: %s -> %s. %s\n", liid, s, d, action))
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(e)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(e)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(e)
  local a = string.format("Datagram (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(e)
  local a = string.format("Stream data (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(e)
  local a = string.format("ICMP (type %d, code %d)", e.type, e.code)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when an IMAP message is observed.
observer.imap = function(e)
  local a = string.format("IMAP (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(e)
  local a = string.format("IMAP SSL (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(e)
  local a = string.format("POP3 (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(e)
  local a = string.format("POP3 SSL (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when a SIP request message is observed.
observer.sip_request = function(e)
  local a = string.format("SIP %s request", e.method)
  observer.describe(e, a)
  io.write(string.format("    From: %s\n", e.from))
  io.write(string.format("    To: %s\n", e.to))
  hexdump(body)
  io.write("\n")
end

-- This function is called when a SIP response message is observed.
observer.sip_response = function(e)
  local a = string.format("SIP response %s %s", e.code, e.status)
  observer.describe(e, a)
  io.write(string.format("    From: %s\n", e.from))
  io.write(string.format("    To: %s\n", e.to))
  hexdump(body)
  io.write("\n")
end

-- This function is called when a SIP SSL message is observed.
observer.sip_ssl = function(e)
 local a = string.format("SIP SSL (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when an SMTP Authentication message is observed.
observer.smtp_auth = function(e)
  local a = string.format("SMTP Authentication (size is %d)", #e.data)
  observer.describe(e, a)
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(e)
  local a = string.format("HTTP %s request", e.method)
  observer.describe(e, a)
  io.write(string.format("    URL %s\n", e.url))

  -- Write header
  for key, value in pairs(e.header) do
    io.write(string.format("    %s: %s\n", key, value))
  end

  hexdump(body)

  io.write("\n")

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(e)

  local a = string.format("HTTP response %s %s", e.code, e.status)
  observer.describe(e, a)
  io.write(string.format("    URL %s\n", e.url))

  local rev = e.context:get_reverse()

  -- Write header
  for key, value in pairs(header) do
    io.write(string.format("    %s: %s\n", e.key, e.value))
  end

  hexdump(e.body)

  io.write("\n")

end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(e)
  local a = string.format("SMTP command %s", e.command)
  observer.describe(e, a)
  io.write("\n")
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(e)
  local a = string.format("SMTP response %d", e.status)
  observer.describe(e, a)
  for k, v in pairs(text) do
    io.write(string.format("    %s\n", v))
  end
  io.write("\n")
end

-- This function is called when an SMTP DATA body is observed.
observer.smtp_data = function(e)
  local a = string.format("SMTP data")
  observer.describe(e, a)
  io.write(string.format("    From: %s\n", e.from))
  for key, value in pairs(e.to) do
    io.write(string.format("    To: %s\n", value))
  end
  hexdump(e.data)
  io.write("\n")
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(e)

  if e.header.qr == 0 then
    observer.describe(e, "DNS query")
  else
    observer.describe(e, "DNS response")
  end

  for key, value in pairs(e.queries) do
    io.write(string.format("    Query: %s\n", value.name))
  end
  
  for key, value in pairs(e.answers) do
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
observer.ftp_command = function(e)
  local a = string.format("FTP command %s", e.command)
  observer.describe(e, a)
  io.write("\n")
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(e)
  local a = string.format("FTP response %d", e.status)
  observer.describe(e, a)
  for k, v in pairs(e.text) do
    io.write(string.format("    %s\n", v))
  end
  io.write("\n")
end

-- This function is called when an NTP timestamp message is observed.
observer.ntp_timestamp_message = function(e)
end

-- This function is called when an NTP control message is observed.
observer.ntp_control_message = function(e)
end

-- This function is called when an NTP private message is observed.
observer.ntp_private_message = function(e)
end

-- This function is called when a gre message is observed.
observer.gre = function(e)
end

-- This function is called when a grep pptp message is observed.
observer.grep_pptp = function(e)
end

-- This function is called when an esp message is observed.
observer.esp = function(e)
end

-- This function is called when an unrecognised ip protocol message is observed.
observer.unrecognised_ip_protocol = function(e)
end

-- This function is called when an 802.11 message is observed.
observer.wlan = function(e)
end

-- This function is called when a tls message is observed.
observer.tls = function(e)
end

-- This function is called when a tls client hello message is observed.
observer.tls_client_hello = function(e)
end

-- This function is called when a tls server hello message is observed.
observer.tls_server_hello = function(e)
end

-- This function is called when a tls certificates message is observed.
observer.tls_certificates = function(e)
end

-- This function is called when a tls server key exchange message is observed.
observer.tls_server_key_exchange = function(e)
end

-- This function is called when a tls server hello done message is observed.
observer.tls_server_hello_done = function(e)
end

-- This function is called when a tls handshake message is observed.
observer.tls_handshake = function(e)
end

-- This function is called when a tls certificate request message is observed.
observer.tls_certificate_request = function(e)
end

-- This function is called when a tls client_key exchange message is observed.
observer.tls_client_key_exchange = function(e)
end

-- This function is called when a tls certificate verify message is observed.
observer.tls_certificate_verify = function(e)
end

-- This function is called when a tls change cipher spec message is observed.
observer.tls_change_cipher_spec = function(e)
end

-- This function is called when a tls handshake finished message is observed.
observer.tls_handshake_finished = function(e)
end

-- This function is called when a tls handshake complete message is observed.
observer.tls_handshake_complete = function(e)
end

-- This function is called when a tls application data message is observed.
observer.tls_application_data = function(e)
end



-- Return the table
return observer

