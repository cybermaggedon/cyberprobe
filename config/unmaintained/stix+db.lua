--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file uses data from a STIX server stored locally in
-- JSON format.  Triggers when STIX Indicators are detected to hit.
--

-- Load JSON decode, and filesystem module.
local mime = require("mime")
local stix = require("util.stix")
local addr = require("util.addresses")
local md5 = require("md5")
local elastic = require("util.elastic")

-- Default TTL on objects.
local default_ttl = "1h"

-- Base64 encoder.
local b64 = function(x)
  local a, b = mime.b64(x)
  return a
end

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Elasticsearch init
elastic.init()

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

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("Connection opened to address %s, hits %s (%s)", 
      v.value, v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "connection_up"
  elastic.submit_observation(obs)

end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)

-- No indicators reported on connection down

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "connection_down"
  elastic.submit_observation(obs)

end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("Unrecognised datagram with address %s, hits %s (%s)", 
      v.value, v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "unrecognised_datagram"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("Connection with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "unrecognised_stream"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, icmp_type, icmp_code, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("ICMP with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "icmp"
  obs["observation"]["type"] = icmp_type
  obs["observation"]["code"] = icmp_code
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when an IMAP message is observed.
observer.imap = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("IMAP with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "imap"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("IMAP SSL with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "imap_ssl"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("POP3 with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "pop3"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("POP3 SSL with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "pop3_ssl"
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)

  -- Hacky.  Construct the URL from bits of stuff we know.
  -- FIXME: URL may already by correct.
  url = "http://" .. header['Host'] .. url

  indicators = {}
  stix.check_url(url, indicators)
  stix.check_hash(md5.sumhexa(body), indicators)
  stix.check_dns(header['Host'], indicators)

  for k, v in pairs(indicators) do
    print(string.format("HTTP request to %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "http_request"
  obs["observation"]["method"] = method
  obs["observation"]["url"] = url
  obs["observation"]["header"] = header
  obs["observation"]["body"] = b64(body)
  elastic.submit_observation(obs)

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)

  indicators = {}
  stix.check_url(url, indicators)
  stix.check_hash(md5.sumhexa(body), indicators)

  for k, v in pairs(indicators) do
    print(string.format("HTTP response from %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "http_response"
  obs["observation"]["code"] = code
  obs["observation"]["status"] = status
  obs["observation"]["header"] = header
  obs["observation"]["url"] = url
  obs["observation"]["body"] = b64(body)
  elastic.submit_observation(obs)

end

-- This function is called when a SIP request message is observed.
observer.sip_request = function(context, method, from, to, data)
end

-- This function is called when a SIP response message is observed.
observer.sip_response = function(context, code, status, from, to, data)
end

-- This function is called when a SIP SSL message is observed.
observer.sip_ssl = function(context, data)
end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("SMTP command with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "smtp_command"
  obs["observation"]["command"] = command
  elastic.submit_observation(obs)

end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("SMTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "smtp_response"
  obs["observation"]["status"] = status
  obs["observation"]["text"] = text
  elastic.submit_observation(obs)

end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)

  indicators = {}

  stix.check_email(from, indicators)

  for k, v in pairs(to) do
    stix.check_email(v, indicators)
  end

  for k, v in pairs(indicators) do
    print(string.format("SMTP email from/to %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "smtp_data"
  obs["observation"]["from"] = from
  obs["observation"]["to"] = to
  obs["observation"]["data"] = b64(data)
  elastic.submit_observation(obs)

end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)

  local trans = "query"
  if header.qr == 1 then
    trans = "response"
  end

  if not(#queries == 1) then
    return
  end

  indicators = {}

  stix.check_dns(queries[1].name, indicators)

  for k, v in pairs(indicators) do
    print(string.format("DNS %s for %s, hits %s (%s)", trans, queries[1].name,
        v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "dns_message"
  obs["observation"]["type"] = trans

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

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("FTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
  obs["observation"]["action"] = "ftp_command"
  obs["observation"]["command"] = command
  elastic.submit_observation(obs)

end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("FTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

  local obs = elastic.initialise_observation(context, indicators)
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

