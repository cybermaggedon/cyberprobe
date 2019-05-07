--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file outputs events as JSON, one JSON event per lie.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

local model = require("util.json")
local json = require("json")

-- The table should contain functions.

-- Call the JSON functions for all observer functions.
observer.trigger_up = model.trigger_up
observer.trigger_down = model.trigger_down
observer.connection_up = model.connection_up
observer.connection_down = model.connection_down
observer.unrecognised_datagram = model.unrecognised_datagram
observer.unrecognised_stream = model.unrecognised_stream
observer.icmp = model.icmp
observer.imap = model.imap
observer.imap_ssl = model.imap_ssl
observer.pop3 = model.pop3
observer.pop3_ssl = model.pop3_ssl
observer.http_request = model.http_request
observer.http_response = model.http_response
observer.sip_request = model.sip_request
observer.sip_response = model.sip_response
observer.sip_ssl = model.sip_ssl
observer.smtp_command = model.smtp_command
observer.smtp_response = model.smtp_response
observer.smtp_data = model.smtp_data
observer.dns_message = model.dns_message
observer.ftp_command = model.ftp_command
observer.ftp_response = model.ftp_response
observer.ntp_timestamp_message = model.ntp_timestamp_message
observer.ntp_control_message = model.ntp_control_message
observer.ntp_private_message = model.ntp_private_message
observer.gre = model.gre
observer.grep_pptp = model.gre_pptp
observer.esp = model.esp
observer.unrecognised_ip_protocol = model.unrecognised_ip_protocol
observer.wlan = model.wlan
observer.tls = model.tls
observer.tls_client_hello = model.tls_client_hello
observer.tls_server_hello = model.tls_server_hello
observer.tls_certificates = model.tls_certificates
observer.tls_server_key_exchange = model.tls_server_key_exchange
observer.tls_server_hello_done = model.tls_server_hello_done
observer.tls_handshake = model.tls_handshake
observer.tls_certificate_request = model.tls_certificate_request
observer.tls_client_key_exchange = model.tls_client_key_exchange

local submit = function(obj)
  data = json.encode(obj)
  print(data)
end

model.init(submit)

-- Return the table
return observer

