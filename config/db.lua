--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file stores events in ElasticSearch.  The event
-- functions are all empty stubs.  Maybe a good starting point for building
-- your own config from scratch.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

local mime = require("mime")
local elastic = require("util.elastic")

local b64 = function(x)
  local a, b = mime.b64(x)
  return a
end

-- Elasticsearch init
elastic.init()

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
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "connected_up"
  elastic.submit_observation(obs)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "connected_down"
  elastic.submit_observation(obs)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "unrecognised_datagram"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "unrecognised_stream"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, icmp_type, icmp_code, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "icmp"
  obs["observation"]["type"] = icmp_type
  obs["observation"]["code"] = icmp_code
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when an IMAP message is observed.
observer.imap = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "imap"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "imap_ssl"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "pop3"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "pop3_ssl"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when a SIP request is observed.
observer.sip_request = function(context, method,from, to, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "sip_request"
  obs["observation"]["method"] = method
  obs["observation"]["from"] = from
  obs["observation"]["to"] = to
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when a SIP response is observed.
observer.sip_response = function(context, code, status, from, to, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "sip_response"
  obs["observation"]["code"] = code
  obs["observation"]["status"] = status
  obs["observation"]["from"] = from
  obs["observation"]["to"] = to
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when a SIP SSL message is observed.
observer.sip_ssl = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "pop3_ssl"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when an SMTP Authentication message is observed.
observer.smtp_auth = function(context, data)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "smtp_auth"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "http_request"
  obs["observation"]["method"] = method
  obs["observation"]["url"] = url
  obs["observation"]["header"] = header
  obs["observation"]["body"] = b64(body)
  elastic.submit_observation(obs)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "http_response"
  obs["observation"]["code"] = code
  obs["observation"]["status"] = status
  obs["observation"]["header"] = header
  obs["observation"]["url"] = url
  obs["observation"]["body"] = b64(body)
  elastic.submit_observation(obs)
end

-- This function is called when a DNS over TCP message is observed.
observer.dns_over_tcp_message = function(context, header, queries, answers, auth, add)
  local obs = elastic.initialise_observation(context)

  obs["observation"]["action"] = "dns_over_tcp_message"

  if header.qr == 0 then
    obs["observation"]["type"] = "query"
  else
    obs["observation"]["type"] = "response"
  end

  local q = {}
  for key, value in pairs(queries) do
    q[#q + 1] = value.name
  end
  obs["observation"]["queries"] = q

  q = {}
  for key, value in pairs(answers) do
    local a = {}
    a["name"] = value.name
    if value.rdaddress then
       a["address"] = value.rdaddress
    end
    if value.rdname then
       a["name"] = value.rdname
    end
    q[#q + 1] = a
  end
  obs["observation"]["answers"] = q
  elastic.submit_observation(obs)
end

-- This function is called when a DNS over UDP message is observed.
observer.dns_over_udp_message = function(context, header, queries, answers, auth, add)
  local obs = elastic.initialise_observation(context)

  obs["observation"]["action"] = "dns_over_udp_message"

  if header.qr == 0 then
    obs["observation"]["type"] = "query"
  else
    obs["observation"]["type"] = "response"
  end

  local q = {}
  for key, value in pairs(queries) do
    q[#q + 1] = value.name
  end
  obs["observation"]["queries"] = q

  q = {}
  for key, value in pairs(answers) do
    local a = {}
    a["name"] = value.name
    if value.rdaddress then
       a["address"] = value.rdaddress
    end
    if value.rdname then
       a["name"] = value.rdname
    end
    q[#q + 1] = a
  end
  obs["observation"]["answers"] = q
  elastic.submit_observation(obs)
end


-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "ftp_command"
  obs["observation"]["command"] = command
  elastic.submit_observation(obs)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local obs = elastic.initialise_observation(context)
  obs["observation"]["action"] = "ftp_response"
  obs["observation"]["status"] = status
  obs["observation"]["text"] = text
  elastic.submit_observation(obs)
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

