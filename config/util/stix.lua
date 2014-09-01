
local lfs = require("lfs")
local jsdec = require("json.decode")

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
  f:close()

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

return stix

