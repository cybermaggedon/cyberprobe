--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file uses data from a STIX server stored locally in
-- JSON format.  Triggers when STIX Indicators are detected to hit.
--

-- Load JSON decode, and filesystem module.
local jsdec = require("json.decode")
local lfs = require("lfs")

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Last mod time of the configuration file.  This helps us work out when to
-- reload.
local cur_mtime = 0

-- Configuration file.
local config_file = "stix-default-combined.json"

-- STIX information gets stored here.
local stix = {}

-- This stores the JSON decode.
stix.configuration = {}

-- This stores an index, from various address information to the STIX
-- Indicators.
stix.index = {}

-- Function, checks the modification time of the configuration file, and
-- if it's changed, reloads and regenerates the index.
stix.check_config = function(file)

  -- Get file mod time.
  local mtime = lfs.attributes(file, "modification")

  -- If modtime is the same, nothing to do.
  if mtime == last_mtime then return end

  -- Read file
  local f = io.open(file, "r")
  stix.configuration = jsdec(f:read("*a"))
  f.close()

  -- Initialise the STIX indexes.
  stix.index = {}
  stix.index.email = {}
  stix.index.user_account = {}
  stix.index.hostname = {}
  stix.index.port = {}
  stix.index.url = {}
  stix.index.ipv4 = {}
  stix.index.mac = {}
  stix.index.file = {}
  stix.index.hash = {}

  -- Loop through indicators.
  for key, value in pairs(stix.configuration.indicators) do

    -- Get indicator object
    local object = value.observable.object.properties

    -- Pull out different interesting things for the index.

    -- Address type
    if object["xsi:type"] == "AddressObjectType" then

      -- Index email address
      if object.category == "e-mail" then
	stix.index.email[object.address_value] = value
      end

      -- Index IPv4 address
      if object.category == "ipv4-addr" then
	stix.index.ipv4[object.address_value] = value
      end

      -- Index MAC address
      if object.category == "mac" then
	stix.index.mac[object.address_value] = value
      end

    -- UserAccount type
    elseif object["xsi:type"] == "UserAccountObjectType" then

      -- Index on concatenation of domain and username.
      if object.domain and object.username then
	ix = object.domain .. "|" .. object.username
	stix.index.user_account[ix] = value
      end

    -- Hostname
    elseif object["xsi:type"] == "HostnameObjectType" then

      -- Index on hostname value
      stix.index.hostname[object.hostname_value] = value

    -- Port
    elseif object["xsi:type"] == "PortObjectType" then

      -- Index on concatenation of layer 4 protocol, and port number.
      if object.port_value and object.layer4_protocol then
	ix = object.layer4_protocol.value .. ":" .. object.port_value
	stix.index.port[ix] = value
      end

    -- URI
    elseif object["xsi:type"] == "URIObjectType" then

      -- Index on the URI itself.
      stix.index.url[object.value] = value

    -- File
    elseif object["xsi:type"] == "FileObjectType" then

      -- Index on pathname
      if object.full_path ~= nil then
	stix.index.file[object.full_path] = value
      end

      -- Index on hash values
      if object.hashes then
	for k2, v2 in pairs(object.hashes) do
	  if v2.type and v2.simple_hash_value then
	    ix = v2.type .. ":" .. v2.simple_hash_value
	    stix.index.hash[ix] = value
	  end
	end
      end
    end
  end

  io.write("Reloaded configuration file.\n")

  -- Update file modification time to modtime of this file.
  last_mtime = mtime

end

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
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
end

-- Call this to check, and if appropriate, update the configuration file
observer.check_config = function()
  stix.check_config(config_file)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)

  observer.check_config()

  -- Hacky.  Construct the URL from bits of stuff we know.
  -- FIXME: URL may already by correct.
  url = "http://" .. header['Host'] .. url

  check = stix.index.url[url]
  if check then
    print(string.format("HTTP request to %s, hits %s (%s)!", url,
        check.id, check.description))
  end

  check = stix.index.hostname[header['Host']]
  if check then
    print(string.format("HTTP request to %s, hits %s (%s)!", header["Host"],
        check.id, check.description))
  end

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)

  observer.check_config()

  check = stix.index.url[url]
  if check then
    print(string.format("HTTP response from %s, hits %s (%s)!", url,
        check.id, check.description))
  end

end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)
end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)

  observer.check_config()

  if header.qr == 0 and #queries == 1 then

    check = stix.index.hostname[queries[1].name]
    if check then
      print(string.format("DNS query for %s, hits %s (%s)!", queries[1].name,
          check.id, check.description))
    end

  end

  if header.qr == 1 and #queries == 1 then

    check = stix.index.hostname[queries[1].name]
    if check then
      print(string.format("DNS response for %s, hits %s (%s)!", queries[1].name,
          check.id, check.description))
    end

  end

end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
end

-- Return the table
return observer

