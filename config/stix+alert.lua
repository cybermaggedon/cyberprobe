--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file uses data from a STIX server stored locally in
-- JSON format.  Triggers when STIX Indicators are detected to hit.
--

-- STIX support.
local stix = require("util.stix")
local addr = require("util.addresses")
local md5 = require("md5")

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

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
    print(string.format("Connection with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("Datagram with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("ICMP with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

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

end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("SMTP command with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("SMTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)

  indicators = {}
  stix.check_email(from, indicators)

  for k, v in pairs(indicators) do
    print(string.format("SMTP email from %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

  indicators = {}
  for k, v in pairs(to) do
    stix.check_email(v, indicators)
  end

  for k, v in pairs(indicators) do
    print(string.format("SMTP email to %s, hits %s (%s)", v.value,
        v.id, v.description))
  end

end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)

  if header.qr == 0 and #queries == 1 then
    indicators = {}
    stix.check_dns(queries[1].name, indicators)
    for k, v in pairs(indicators) do
      print(string.format("DNS query for %s, hits %s (%s)", queries[1].name,
          v.id, v.description))
    end
  end

  if header.qr == 1 and #queries == 1 then
    indicators = {}
    stix.check_dns(queries[1].name, indicators)
    for k, v in pairs(indicators) do
      print(string.format("DNS response for %s, hits %s (%s)", queries[1].name,
          v.id, v.description))
    end
  end

end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("FTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)

  indicators = {}
  stix.check_addresses(context, indicators)

  for k, v in pairs(indicators) do
    print(string.format("FTP response with address %s, hits %s (%s)", v.value,
      v.id, v.description))
  end

end

-- Return the table
return observer

