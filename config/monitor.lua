--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display a summary of all
-- observered events.  This can serve as a template.
--

local addr = require("util.addresses")

-- hex encoding
local str_to_hex = function(x)
  return "0x" .. x:gsub('.', function (c)
      return string.format('%02X', string.byte(c))
    end)
end

local mime = require("mime")
-- Base64 encoding
local b64 = function(x)
  local a, b = mime.b64(x)
  if (a == nil) then
    return ""
  end
  return a
end


-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- The table should contain functions.

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(e)
  io.write(string.format("%s: Target %s detected at address %s\n\n", e.time, e.device, e.address))
  io.flush()
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(e)
  io.write(string.format("Target %s gone off air\n\n", e.device))
  io.flush()
end

-- Puts out a one-line description of the event.  Parameter action is a
-- description of the event.
observer.describe = function(e, action)
  local device = e.device
  local s = addr.describe_address(e.context, true)
  local d = addr.describe_address(e.context, false)
  io.write(string.format("%s: %s -> %s. %s\n", device, s, d, action))
--  io.write(string.format("    Time: %s\n", e.time))
  io.flush()
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(e)
  --observer.describe(e, "Connected")
  --io.write("\n")
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(e)
  --observer.describe(e, "Disconnected")
  --io.write("\n")
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(e)
  local a = string.format("Datagram (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(e)
  local a = string.format("Stream data (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(e)
  local a = string.format("ICMP (type %d, class %d)", e.type, e.code)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when an IMAP message is observed.
observer.imap = function(e)
  local a = string.format("IMAP (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(e)
  local a = string.format("IMAP SSL (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(e)
  local a = string.format("POP3 (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(e)
  local a = string.format("POP3 SSL (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when a RTP message is observed.
observer.rtp = function(e)
  local a = string.format("RTP (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when a RTP SSL message is observed.
observer.rtp_ssl = function(e)
  local a = string.format("RTP SSL (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when a SIP request message is observed.
observer.sip_request = function(e)
  local a = string.format("SIP %s request", e.method)
  observer.describe(e, a)
  io.write(string.format("    From: %s\n", e.from))
  io.write(string.format("    To: %s\n", e.to))
  io.write("\n")
  io.flush()
end

-- This function is called when a SIP response message is observed.
observer.sip_response = function(e)
  local a = string.format("SIP response %s %s", e.code, e.status)
  observer.describe(e, a)
  io.write(string.format("    From: %s\n", e.from))
  io.write(string.format("    To: %s\n", e.to))
  io.write("\n")
  io.flush()
end

-- This function is called when a SIP SSL message is observed.
observer.sip_ssl = function(e)
  local a = string.format("SIP SSL (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when an SMTP Authentication message is observed.
observer.smtp_auth = function(e)
  local a = string.format("SMTP Authentication (size is %d)", #e.data)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
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

  io.write("\n")
  io.flush()

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(e)

  local a = string.format("HTTP response %s %s", e.code, e.status)
  observer.describe(e, a)
  io.write(string.format("    URL %s\n", e.url))

  local rev = e.context:get_reverse()

  -- Write header
  for key, value in pairs(e.header) do
    io.write(string.format("    %s: %s\n", key, value))	
  end

  io.write("\n")
  io.flush()

end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(e)
  local a = string.format("SMTP command %s", e.command)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(e)
  local a = string.format("SMTP response %d", e.status)
  observer.describe(e, a)
  for k, v in pairs(e.text) do
    io.write(string.format("    %s\n", v))
  end
  io.write("\n")
  io.flush()
end

-- This function is called when an SMTP DATA body is observed.
observer.smtp_data = function(e)
  local a = string.format("SMTP data")
  observer.describe(e, a)
  io.write(string.format("    From: %s\n", e.from))
  for key, value in pairs(e.to) do
    io.write(string.format("    To: %s\n", value))
  end
  io.write("\n")
  io.flush()
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(e)

  if e.header.qr == 0 then
    observer.describe(e, "DNS query")
  else
    observer.describe(e, "DNS response")
  end

  for key, value in pairs(e.queries) do
    io.write(string.format("    Query: name=%s, type=%s, class=%s\n", value.name, value.type, value.class))
  end
  
  for key, value in pairs(e.answers) do
    io.write(string.format("    Answer: name=%s, type=%s, class=%s", value.name, value.type, value.class))
    if value.rdaddress then
       io.write(string.format(" -> %s", value.rdaddress))
    end
    if value.rdname then
       io.write(string.format(" -> %s", value.rdname))
    end
    io.write("\n")
  end

  io.write("\n")
  io.flush()	

end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(e)
  local a = string.format("FTP command %s", e.command)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(e)
  local a = string.format("FTP response %d", e.status)
  observer.describe(e, a)
  for k, v in pairs(e.text) do
    io.write(string.format("    %s\n", v))
  end
  io.write("\n")
  io.flush()
end

-- Common ntp function
observer.ntp_common = function(header)
  io.write(string.format("    Leap Indicator      -> %u\n", header.leap_indicator));
  io.write(string.format("    Version             -> %u\n", header.version));
  io.write(string.format("    Mode                -> %u\n", header.mode));

  io.flush()
end

-- This function is called when a NTP Timestamp message is observed.
observer.ntp_timestamp_message = function(e)
  local a = string.format("NTP Timestamp")
  observer.describe(e, a);
  observer.ntp_common(e.header);  
  io.write(string.format("    Stratum             -> %u\n", e.timestamp.stratum));
  io.write(string.format("    Poll                -> %u\n", e.timestamp.poll));
  io.write(string.format("    Precision           -> %.6f\n", e.timestamp.precision));
  io.write(string.format("    Root Delay          -> %.6f\n", e.timestamp.root_delay));
  io.write(string.format("    Root Dispersion     -> %.6f\n", e.timestamp.root_dispersion));
  io.write(string.format("    Reference Id        -> %u\n", e.timestamp.reference_id));
  io.write(string.format("    Reference Timestamp -> %.9f\n", e.timestamp.reference_timestamp));
  io.write(string.format("    Originate Timestamp -> %.9f\n", e.timestamp.originate_timestamp));
  io.write(string.format("    Receive Timestamp   -> %.9f\n", e.timestamp.receive_timestamp));
  io.write(string.format("    Transmit Timestamp  -> %.9f\n", e.timestamp.transmit_timestamp));
  io.write(string.format("    Extension           -> %s\n", e.timestamp.extension));
  io.write("\n")
  io.flush()
end

-- This function is called when a NTP Control message is observed.
observer.ntp_control_message = function(e)
  local a = string.format("NTP Control")
  observer.describe(e, a);
  observer.ntp_common(e.header);
  io.write(string.format("  Type                -> %s\n", e.control.type));
  io.write(string.format("  Error               -> %s\n", e.control.error));
  io.write(string.format("  Fragment            -> %s\n", e.control.fragment));
  io.write(string.format("  Operation           -> %u\n", e.control.opcode));
  io.write(string.format("  Sequence            -> %u\n", e.control.sequence));
  io.write(string.format("  Status              -> %u\n", e.control.status));
  io.write(string.format("  Association         -> %u\n", e.control.association_id));
  io.write(string.format("  Offset              -> %u\n", e.control.offset));
  io.write(string.format("  Data Length         -> %u\n", e.control.data_length));
  io.write(string.format("  Authentication      -> %s\n", e.control.authentication));
  io.write("\n")
  io.flush()
end

-- This function is called when a NTP Private message is observed.
observer.ntp_private_message = function(e)
  local a = string.format("NTP Private")
  observer.describe(e, a);
  observer.ntp_common(e.header);
  io.write(string.format("  Auth                -> %s\n", e.private.auth));
  io.write(string.format("  Sequence            -> %u\n", e.private.sequence));
  io.write(string.format("  Implementation      -> %u\n", e.private.implementation));
  io.write(string.format("  Request Code        -> %u\n", e.private.request_code));
  io.write("\n")
  io.flush()
end

-- This function is called when a gre message is observed.
observer.gre = function(e)
  local a = string.format("GRE")
  observer.describe(e, a);
  io.write(string.format("  Next Proto             -> %s\n", e.next_proto));
  io.write(string.format("  Key                    -> %u\n", e.key));
  io.write(string.format("  Sequence Number        -> %u\n", e.sequence_number));
  io.write(string.format("  Payload Size           -> %u\n", string.len(e.payload)));
  io.write("\n")
  io.flush()
end

-- This function is called when a grep pptp message is observed.
observer.grep_pptp = function(e)
  local a = string.format("GRE PPTP")
  observer.describe(e, a);
  io.write(string.format("  Next Proto             -> %s\n", e.next_proto));
  io.write(string.format("  Call ID                -> %u\n", e.call_id));
  io.write(string.format("  Sequence Number        -> %u\n", e.sequence_number));
  io.write(string.format("  Acknowledgement Number -> %u\n", e.acknowledgement_number));
  io.write(string.format("  Payload Size           -> %u\n", e.payload_length));
  io.write("\n")
  io.flush()
end

-- This function is called when an esp message is observed.
observer.esp = function(e)
  local a = string.format("ESP")
  observer.describe(e, a);
  io.write(string.format("  SPI             -> %s\n", e.spi));
  io.write(string.format("  Sequence Number -> %u\n", e.sequence_number));
  io.write(string.format("  Payload Size    -> %u\n", e.payload_length));
  io.write("\n")
  io.flush()
end

-- This function is called when an unrecognised ip protocol message is observed.
observer.unrecognised_ip_protocol = function(e)
  local a = string.format("Unrecognised IP")
  observer.describe(e, a);
  io.write(string.format("  Next Proto   -> %u\n", e.next_proto));
  io.write(string.format("  Payload Size -> %u\n", e.payload_length));
  io.write("\n")
  io.flush()
end

-- This function is called when an 802.11 message is observed.
observer.wlan = function(e)
  local a = string.format("802.11")
  observer.describe(e, a);
  io.write(string.format("  Version              -> %u\n", e.version));
  io.write(string.format("  Type                 -> %u\n", e.type));
  io.write(string.format("  Sub Type             -> %u\n", e.subtype));
  io.write(string.format("  Flags                -> %u\n", e.flags));
  io.write(string.format("  Protected            -> %u\n", e.protected));
  io.write(string.format("  Duration             -> %u\n", e.duration));
  io.write(string.format("  Filter address       -> %s\n", e.filt_addr));
  io.write(string.format("  Fragmentation number -> %u\n", e.frag_num));
  io.write(string.format("  Sequence number      -> %u\n", e.seq_num));
  io.write("\n")
  io.flush()
end

-- This function is called when an unknown tls message is observed.
observer.tls_unknown = function(e)
  local a = string.format("TLS unknown")
  observer.describe(e, a);
  io.write(string.format("  Version      -> %s\n", e.version));
  io.write(string.format("  Content Type -> %u\n", e.content_type));
  io.write(string.format("  Length       -> %u\n", e.length));
  io.write("\n")
  io.flush()
end

-- This function is called when a tls client hello message is observed.
observer.tls_client_hello = function(e)
  local a = string.format("TLS Client Hello")
  observer.describe(e, a);
  io.write(string.format("  Version             -> %s\n", e.version));
  io.write(string.format("  Session ID          -> %s\n", e.session_id));
  io.write("  Random              -> \n");
  io.write(string.format("    timestamp         -> %u\n", e.random_timestamp));
  io.write(string.format("    data              -> %s\n", str_to_hex(e.random_data)));
  io.write("  Cipher suites       -> \n");
  for key, value in pairs(e.cipher_suites) do
    io.write(string.format("                      -> %s\n", value.name));
  end
  io.write("  Compression Methods -> \n");
  for key, value in pairs(e.compression_methods) do
    io.write(string.format("                    -> %s\n", value.name));
  end
  io.write("  Extensions        -> \n");
  for key, value in pairs(e.extensions) do
    io.write(string.format("  - name            -> %s\n", value.name));
    io.write(string.format("    length          -> %s\n", value.length));
    if string.len(value.data) > 0 then
      io.write(string.format("    data            -> %s\n", str_to_hex(value.data)));
    end
  end
  io.write("\n")
  io.flush()
end

-- This function is called when a tls server hello message is observed.
observer.tls_server_hello = function(e)
  local a = string.format("TLS Server Hello")
  observer.describe(e, a);
  io.write(string.format("  Version             -> %s\n", e.version));
  io.write(string.format("  Session ID          -> %s\n", e.session_id));
  io.write("  Random              -> \n");
  io.write(string.format("    timestamp         -> %u\n", e.random_timestamp));
  io.write(string.format("    data              -> %s\n", str_to_hex(e.random_data)));
  io.write(string.format("  Cipher suite        -> %s\n", e.cipher_suite.name));
  io.write(string.format("  Compression Method  -> %s\n", e.compression_method.name));
  io.write("  Extensions          -> \n");
  for key, value in pairs(e.extensions) do
    io.write(string.format("    name            -> %s\n", value.name));
    io.write(string.format("    length          -> %s\n", value.length));
    if string.len(value.data) > 0 then
      io.write(string.format("    data            -> %s\n", str_to_hex(value.data)));
    end
  end
  io.write("\n")
  io.flush()
end

-- This function is called when a tls certificates message is observed.
observer.tls_certificates = function(e)
  local a = string.format("TLS Certificates")
  observer.describe(e, a);
  io.write("  Certificates  -> \n");
  for key, value in pairs(e.certificates) do
    io.write(string.format("                -> %s\n", b64(value)));
  end
  io.write("\n")
  io.flush()
end

-- This function is called when a tls server key exchange message is observed.
observer.tls_server_key_exchange = function(e)
  local a = string.format("TLS Server Key Exchange")
  observer.describe(e, a);
  io.write(string.format("  Key Exchange Algorithm   -> %s\n", e.key_exchange_algorithm));
  if e.key_exchange_algorithm == "ec-dh" then
    io.write(string.format("  Curve Metadata           -> %s\n", e.curve_metadata));
    io.write(string.format("  Public Key               -> %s\n", b64(e.public_key)));
    io.write(string.format("  Signature Hash Algorithm -> %s\n", e.signature_hash_algorithm));
    io.write(string.format("  Signature Algorithm      -> %s\n", e.signature_algorithm));
    io.write(string.format("  Signature Hash           -> %s\n", e.signature_hash));
  end
  io.write("\n")
  io.flush()
end

-- This function is called when a tls server hello done message is observed.
observer.tls_server_hello_done = function(e)
  local a = string.format("TLS Server Hello Done")
  observer.describe(e, a);
  io.write("\n")
  io.flush()
end

-- This function is called when a tls handshake message is observed.
observer.tls_handshake_unknown = function(e)
  local a = string.format("TLS Handshake Unknown Message")
  observer.describe(e, a);
  io.write(string.format("  Type    -> %u\n", e.type));
  io.write(string.format("  Length  -> %u\n", e.length));
  io.write("\n")
  io.flush()
end

-- This function is called when a tls certificate request message is observed.
observer.tls_certificate_request = function(e)
  local a = string.format("TLS Certificate Request")
  observer.describe(e, a);
  io.write("  Cert Types            -> \n");
  for key, value in pairs(e.cert_types) do
    io.write(string.format("                        -> %s\n", value));
  end
  io.write("  Signature Algorithms  -> \n");
  for key, value in pairs(e.signature_algorithms) do
    io.write(string.format("    Hash Algorithm      -> %s\n", value.hash_algorithm));
    io.write(string.format("    Signature Algorithm -> %s\n", value.signature_algorithm));
  end
  io.write(string.format("  Distinguished Names  -> %s\n", str_to_hex(e.distinguished_names)));
  io.write("\n")
  io.flush()
end

-- This function is called when a tls client_key exchange message is observed.
observer.tls_client_key_exchange = function(e)
  local a = string.format("TLS Client Key Exchange")
  observer.describe(e, a);
  io.write(string.format(" Key  -> %s\n", b64(e.key)));
  io.write("\n")
  io.flush()
end

-- This function is called when a tls certificate verify message is observed.
observer.tls_certificate_verify = function(e)
  local a = string.format("TLS Certificate Verify")
  observer.describe(e, a);
  io.write("  Signature Algorithm   -> \n");
  io.write(string.format("    Hash Algorithm      -> %s\n", e.signature_algorithm.hash_algorithm));
  io.write(string.format("    Signature Algorithm -> %s\n", e.signature_algorithm.signature_algorithm));
  io.write(string.format("  Signature             -> %s\n", e.signature));
  io.write("\n")
  io.flush()
end

-- This function is called when a tls change cipher spec message is observed.
observer.tls_change_cipher_spec = function(e)
  local a = string.format("TLS Change Cipher Spec")
  observer.describe(e, a);
  io.write(string.format("  Value -> %u\n", e.val));
  io.write("\n")
  io.flush()
end

-- This function is called when a tls handshake finished message is observed.
observer.tls_handshake_finished = function(e)
  local a = string.format("TLS Handshake Finished")
  observer.describe(e, a);
  io.write(string.format("  Message Length -> %u\n", #e.message));
  io.write("\n")
  io.flush()
end

-- This function is called when both sides of the handshake have finished.
observer.tls_handshake_complete = function(e)
  local a = string.format("TLS Handshake Complete")
  observer.describe(e, a);
  io.write("\n")
  io.flush()
end

-- This function is called when a tls application data message is observed.
observer.tls_application_data = function(e)
  local a = string.format("TLS Application Data")
  observer.describe(e, a);
  io.write(string.format("  Version        -> %s\n", e.version));
  io.write(string.format("  Message Length -> %u\n", #e.data));
  io.write("\n")
  io.flush()
end

observer.event_handlers = {
  trigger_up = observer.trigger_up,
  trigger_down = observer.trigger_down,
  describe = observer.describe,
  connection_up = observer.connection_up,
  connection_down = observer.connection_down,
  unrecognised_datagram = observer.unrecognised_datagram,
  unrecognised_stream = observer.unrecognised_stream,
  icmp = observer.icmp,
  imap = observer.imap,
  imap_ssl = observer.imap_ssl,
  pop3 = observer.pop3,
  pop3_ssl = observer.pop3_ssl,
  rtp = observer.rtp,
  rtp_ssl = observer.rtp_ssl,
  sip_request = observer.sip_request,
  sip_response = observer.sip_response,
  sip_ssl = observer.sip_ssl,
  smtp_auth = observer.smtp_auth,
  http_request = observer.http_request,
  http_response = observer.http_response,
  smtp_command = observer.smtp_command,
  smtp_response = observer.smtp_response,
  smtp_data = observer.smtp_data,
  dns_message = observer.dns_message,
  ftp_command = observer.ftp_command,
  ftp_response = observer.ftp_response,
  ntp_common = observer.ntp_common,
  ntp_timestamp_message = observer.ntp_timestamp_message,
  ntp_control_message = observer.ntp_control_message,
  ntp_private_message = observer.ntp_private_message,
  gre = observer.gre,
  grep_pptp = observer.grep_pptp,
  esp = observer.esp,
  unrecognised_ip_protocol = observer.unrecognised_ip_protocol,
  wlan = observer.wlan,
  tls_unknown = observer.tls_unknown,
  tls_client_hello = observer.tls_client_hello,
  tls_server_hello = observer.tls_server_hello,
  tls_certificates = observer.tls_certificates,
  tls_server_key_exchange = observer.tls_server_key_exchange,
  tls_server_hello_done = observer.tls_server_hello_done,
  tls_handshake_unknown = observer.tls_handshake_unknown,
  tls_certificate_request = observer.tls_certificate_request,
  tls_client_key_exchange = observer.tls_client_key_exchange,
  tls_certificate_verify = observer.tls_certificate_verify,
  tls_change_cipher_spec = observer.tls_change_cipher_spec,
  tls_handshake_finished = observer.tls_handshake_finished,
  tls_handshake_complete = observer.tls_handshake_complete,
  tls_application_data = observer.tls_application_data
}

observer.event = function(e)
  fn = observer.event_handlers[e.action]
  fn(e)
end


-- Return the table
return observer

