--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with zeromq pub/sub, so that network events are
-- presented as pub/sub events.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local json = require("json")
local lzmq = require("lzmq")
local os = require("os")
local model = require("util.json")

-- Config ------------------------------------------------------------------

--
-- To offer a local publication port: either just do nothing, and accept
-- the default 5555 port, or set ZMQ_BINDING to something like tcp://*:12345
-- to specify the port number.  To push to a remote port, 
local binding
local connection
if os.getenv("ZMQ_BINDING") then
  binding = os.getenv("ZMQ_BINDING")
else
  if os.getenv("ZMQ_CONNECT") then
    connection = os.getenv("ZMQ_CONNECT")
  else
    binding = "tcp://*:5555"
  end
end

-- Local socket state
local context
local skt

-- Initialise.
local init = function()

  context = lzmq.context()

  if binding then
    skt = context:socket(lzmq.PUB)
    ret = skt:bind(binding)

    if ret == false then
      print("ZeroMQ bind failed")
      os.exit(1)
    end
  else
     skt = context:socket(lzmq.PUSH)
     ret = skt:connect(connection)

     if ret == false then
       print("ZeroMQ connect failed")
       os.exit(1)
    end
 end

end

-- ZeroMQ object submission function - just pushes the object onto the queue.
local submit = function(obs)
  ret = skt:send(json.encode(obs))
end

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

-- Register Redis submission.
model.init(submit)

-- Initialise
init()

-- Return the table
return observer

