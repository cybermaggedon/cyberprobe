--
-- Cybermon utility, to output JSON model data.
-- 

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local module = {}

-- Other modules -----------------------------------------------------------

local mime = require("mime")
local json = require("json")
local os = require("os")
local dns = require("util.dns")

-- Initialise UUID ---------------------------------------------------------

-- Needed to help initialise UUID.
local uuid = require("uuid")
local string = require("string")

uuid.seed()

-- Initialise, register a submit function. ---------------------------------
local submit
module.init = function(s)
  submit = s
end

-- GeoIP -------------------------------------------------------------------

-- Open geoip module if it exists.
local geoip
status, rtn, geoip = pcall(function() return require("geoip.country") end)
if status then
  geoip = rtn
end 

-- Open geoip database if it exists.
local geodb
if geoip then
  geodb = geoip.open()
  print("Using GeoIP: " .. tostring(geodb))
end

-- Base64 encoding
local b64 = function(x)
  local a, b = mime.b64(x)
  if (a == nil) then
    return ""
  end
  return a
end

-- Gets the stack of addresses on the src/dest side of a context.
local function get_stack(context, addrs, is_src)

  local par = context:get_parent()

  if par then
    get_stack(par, addrs, is_src)
  end

  local cls, addr
  if is_src then
    cls, addr = context:get_src_addr()
  else
    cls, addr = context:get_dest_addr()
  end

  if cls == "root" then
    return
  end

  if addr == "" then
    table.insert(addrs, cls)
  else
    table.insert(addrs, cls .. ":" .. addr)
  end
  
end

-- Initialise a basic observation
local initialise_observation = function(context, indicators)

  local obs = {}
  obs["device"] = context:get_liid()

  local addrs = {}
  get_stack(context, addrs, true)
  obs["src"] = addrs

  addrs = {}
  get_stack(context, addrs, false)
  obs["dest"] = addrs

  if indicators and not(#indicators == 0) then
    obs["indicators"] = {}
    obs["indicators"]["on"] = {}
    obs["indicators"]["description"] = {}
    obs["indicators"]["value"] = {}
    obs["indicators"]["id"] = {}
    for key, value in pairs(indicators) do
      table.insert(obs["indicators"]["on"], value["on"])
      table.insert(obs["indicators"]["description"], value["description"])
      table.insert(obs["indicators"]["value"], value["value"])
      table.insert(obs["indicators"]["id"], value["id"])
    end
  end

  local tm = context:get_event_time()
  local tmstr = os.date("!%Y-%m-%dT%H:%M:%S", math.floor(tm))
  local millis = 1000 * (tm - math.floor(tm))

  tmstr = tmstr .. "." .. string.format("%03dZ", math.floor(millis))

  obs["time"] = tmstr
  obs["id"] = uuid()

  return obs

end

module.initialise_observation = initialise_observation

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
module.trigger_up = function(liid, addr)
end

-- This function is called when an attacker goes off the air
module.trigger_down = function(liid)
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
module.connection_up = function(context)
  local obs = initialise_observation(context)
  obs["action"] = "connected_up"
  submit(obs)
end

-- This function is called when a stream-orientated connection is closed
module.connection_down = function(context)
  local obs = initialise_observation(context)
  obs["action"] = "connected_down"
  submit(obs)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
module.unrecognised_datagram = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "unrecognised_datagram"
  obs["unrecognised_datagram"] = {}
  obs["unrecognised_datagram"]["payload"] = b64(data)
  submit(obs)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
module.unrecognised_stream = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "unrecognised_stream"
  obs["unrecognised_stream"] = {}
  obs["unrecognised_stream"]["payload"] = b64(data)
  submit(obs)
end

-- This function is called when an ICMP message is observed.
module.icmp = function(context, icmp_type, icmp_code, data)
  local obs = initialise_observation(context)
  obs["action"] = "icmp"
  obs["icmp"] = { type=icmp_type, code=icmp_code, payload=b64(data) }
  submit(obs)
end

-- This function is called when an HTTP request is observed.
module.http_request = function(context, method, url, header, body)
  local obs = initialise_observation(context)
  obs["action"] = "http_request"
  obs["url"] = url
  obs["http_request"] = { method=method, header=header }
  if not(body == "") then
    obs["http_request"]["body"] = b64(body)
  end
  submit(obs)
end

-- This function is called when an HTTP response is observed.
module.http_response = function(context, code, status, header, url, body)
  local obs = initialise_observation(context)
  obs["action"] = "http_response"
  obs["url"] = url
  obs["http_response"] = {}
  obs["http_response"]["code"] = code
  obs["http_response"]["status"] = status
  obs["http_response"]["header"] = header
  obs["http_response"]["body"] = b64(body)
  submit(obs)
end

-- This function is called when a DNS message is observed.
module.dns_message = function(context, header, queries, answers, auth, add)

  local obs = initialise_observation(context)

  obs["action"] = "dns_message"
  obs["dns_message"] = {}

  if header.qr == 0 then
    obs["dns_message"]["type"] = "query"
  else
    obs["dns_message"]["type"] = "response"
  end

  local q = {}
  json.util.InitArray(q)
  for key, value in pairs(queries) do
    local a = {}
    a["name"] = value.name
    if dns.type_name[value.type] == nil then
      a["type"] = tostring(value.type)
    else
      a["type"] = dns.type_name[value.type]
    end
    a["class"] = dns.class_name[value.class]
    q[#q + 1] = a
  end
  obs["dns_message"]["query"] = q

  q = {}
  json.util.InitArray(q)
  for key, value in pairs(answers) do
    local a = {}
    a["name"] = value.name
    if dns.type_name[value.type] == nil then
      a["type"] = tostring(value.type)
    else
      a["type"] = dns.type_name[value.type]
    end
    a["class"] = dns.class_name[value.class]
    if value.rdaddress then
       a["address"] = value.rdaddress
    end
    if value.rdname then
       a["name"] = value.rdname
    end
    q[#q + 1] = a
  end
  obs["dns_message"]["answer"] = q
  
  submit(obs)

end

-- This function is called when an FTP command is observed.
module.ftp_command = function(context, command)
  local obs = initialise_observation(context)
  obs["action"] = "ftp_command"
  obs["ftp_command"] = { command=command }
  submit(obs)
end

-- This function is called when an FTP response is observed.
module.ftp_response = function(context, status, text)
  local obs = initialise_observation(context)
  obs["action"] = "ftp_response"
  obs["ftp_response"] = { status=status, text=text }
  submit(obs)
end

-- This function is called when a SIP request message is observed.
module.sip_request = function(context, method, from, to, data)
  local obs = initialise_observation(context)
  obs["action"] = "sip_request"
  obs["sip_request"] = { method=method, from=from, to=to, body=data,
  	payload=b64(data) }
end

-- This function is called when a SIP response message is observed.
module.sip_response = function(context, code, status, from, to, data)
  local obs = initialise_observation(context)
  obs["action"] = "sip_response"
  obs["sip_response"] = { code=code, status=status, from=from, to=to,
  	payload=b64(data) }
  submit(obs)
end

-- This function is called when a SIP SSL message is observed.
module.sip_ssl = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "sip_ssl"
  obs["sip_ssl"] = { payload=b64(data) }
  submit(obs)
end

-- This function is called when an IMAP message is observed.
module.imap = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "imap"
  obs["imap"] = { payload=b64(data) }
  submit(obs)
end

-- This function is called when an IMAP SSL message is observed.
module.imap_ssl = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "imap_ssl"
  obs["imap_ssl"] = { payload=b64(data) }
  submit(obs)
end

-- This function is called when a POP3 message is observed.
module.pop3 = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "pop3"
  obs["pop3"] = { payload=b64(data) }
  submit(obs)
end

-- This function is called when a POP3 SSL message is observed.
module.pop3_ssl = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "pop3_ssl"
  obs["pop3_ssl"] = { payload=b64(data) }
  submit(obs)
end

-- This function is called when an SMTP command is observed.
module.smtp_command = function(context, command)
  local obs = initialise_observation(context)
  obs["action"] = "smtp_command"
  obs["smtp_command"] = { command=command }
  submit(obs)
end

-- This function is called when an SMTP response is observed.
module.smtp_response = function(context, status, text)
  local obs = initialise_observation(context)
  obs["action"] = "smtp_response"
  obs["smtp_response"] = { status=status, text=text }
  submit(obs)
end

-- This function is called when an SMTP response is observed.
module.smtp_data = function(context, from, to, data)
  local obs = initialise_observation(context)
  obs["action"] = "smtp_data"
  obs["smtp_data"] = { from=from, to=to, body=data }
  submit(obs)
end

-- This function is called when a NTP timestamp message is observed.
module.ntp_timestamp_message = function(context, hdr, info)
  local obs = initialise_observation(context)
  obs["action"] = "ntp_timestamp"
  obs["ntp_timestamp"] = { version=hdr.version, mode=hdr.mode }
  submit(obs)
end

-- This function is called when a NTP control message is observed.
module.ntp_control_message = function(context, hdr, info)
  local obs = initialise_observation(context)
  obs["action"] = "ntp_control"
  obs["ntp_control"] = { version=hdr.version, mode=hdr.mode }
  submit(obs)
end

-- This function is called when an NTP private message is observed.
module.ntp_private_message = function(context, hdr, info)
  local obs = initialise_observation(context)
  obs["action"] = "ntp_private"
  obs["ntp_private"] = { version=hdr.version, mode=hdr.mode }
  submit(obs)
end

-- Return the table
return module

