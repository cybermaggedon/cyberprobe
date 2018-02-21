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

local socket = require "socket"
local sha1 = require 'sha1'
local bit32 = require 'bit32'
local timeMS = socket.gettime()*1000
local hostname = io.popen("uname -n"):read()
local seedInput = hostname .. timeMS

-- seed only excepts 32 bit numbers, so hash the input and extract last 32 bits
local seedData = string.sub(sha1.binary(seedInput) , -4,-1)
local seed = string.byte(seedData,4)
seed = seed + bit32.lshift(string.byte(seedData,3),8)
seed = seed + bit32.lshift(string.byte(seedData,2),16)
seed = seed + bit32.lshift(string.byte(seedData,1),24)

uuid.randomseed(seed)

-- Initialise, register a submit function. ---------------------------------
local submit
module.init = function(s)
  submit = s
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
local initialise_observation = function(e, indicators)

  local obs = {}
  obs["device"] = e.context:get_liid()

  net, s, a = e.context:get_network_info()
  if not(net == "") then
    obs["network"] = net
  end

  local addrs = {}
  get_stack(e.context, addrs, true)
  obs["src"] = addrs

  addrs = {}
  get_stack(e.context, addrs, false)
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

  obs["time"] = e.time
  obs["id"] = uuid()

  return obs

end

module.initialise_observation = initialise_observation

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
module.trigger_up = function(e)
end

-- This function is called when an attacker goes off the air
module.trigger_down = function(e)
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
module.connection_up = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "connected_up"
  submit(obs)
end

-- This function is called when a stream-orientated connection is closed
module.connection_down = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "connected_down"
  submit(obs)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
module.unrecognised_datagram = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "unrecognised_datagram"
  obs["unrecognised_datagram"] = {}
  local payload = b64(e.data)
  obs["unrecognised_datagram"]["payload"] = payload
  obs["unrecognised_datagram"]["payload-length"] = e.data:len()
  obs["unrecognised_datagram"]["payload-b64length"] = payload:len()
  obs["unrecognised_datagram"]["payload-sha1"] = sha1(e.data)
  submit(obs)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
module.unrecognised_stream = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "unrecognised_stream"
  obs["unrecognised_stream"] = {}
  local payload = b64(e.data)
  obs["unrecognised_stream"]["payload"] = payload
  obs["unrecognised_stream"]["payload-length"] = e.data:len()
  obs["unrecognised_stream"]["payload-b64length"] = payload:len()
  obs["unrecognised_stream"]["payload-sha1"] = sha1(e.data)
  submit(obs)
end

-- This function is called when an ICMP message is observed.
module.icmp = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "icmp"
  obs["icmp"] = { type=e.type, code=e.code, payload=b64(e.data) }
  submit(obs)
end

-- This function is called when an HTTP request is observed.
module.http_request = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "http_request"
  obs["url"] = e.url
  obs["http_request"] = { method=e.method, header=e.header }
  if not(e.body == "") then
    obs["http_request"]["body"] = b64(e.body)
  end
  submit(obs)
end

-- This function is called when an HTTP response is observed.
module.http_response = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "http_response"
  obs["url"] = e.url
  obs["http_response"] = {}
  obs["http_response"]["code"] = e.code
  obs["http_response"]["status"] = e.status
  obs["http_response"]["header"] = e.header
  obs["http_response"]["body"] = b64(e.body)
  submit(obs)
end

-- This function is called when a DNS message is observed.
module.dns_message = function(e)

  local obs = initialise_observation(e)

  obs["action"] = "dns_message"
  obs["dns_message"] = {}

  if e.header.qr == 0 then
    obs["dns_message"]["type"] = "query"
  else
    obs["dns_message"]["type"] = "response"
  end

  local q = {}
  json.util.InitArray(q)
  for key, value in pairs(e.queries) do
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
  for key, value in pairs(e.answers) do
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
module.ftp_command = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "ftp_command"
  obs["ftp_command"] = { command=e.command }
  submit(obs)
end

-- This function is called when an FTP response is observed.
module.ftp_response = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "ftp_response"
  obs["ftp_response"] = { status=e.status, text=e.text }
  submit(obs)
end

-- This function is called when a SIP request message is observed.
module.sip_request = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "sip_request"
  obs["sip_request"] = { method=e.method, from=e.from, to=e.to, body=e.data,
  	payload=b64(e.data) }
end

-- This function is called when a SIP response message is observed.
module.sip_response = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "sip_response"
  obs["sip_response"] = { code=e.code, status=e.status, from=e.from, to=e.to,
  	payload=b64(e.data) }
  submit(obs)
end

-- This function is called when a SIP SSL message is observed.
module.sip_ssl = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "sip_ssl"
  obs["sip_ssl"] = { payload=b64(e.data) }
  submit(obs)
end

-- This function is called when an IMAP message is observed.
module.imap = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "imap"
  obs["imap"] = { payload=b64(e.data) }
  submit(obs)
end

-- This function is called when an IMAP SSL message is observed.
module.imap_ssl = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "imap_ssl"
  obs["imap_ssl"] = { payload=b64(e.data) }
  submit(obs)
end

-- This function is called when a POP3 message is observed.
module.pop3 = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "pop3"
  obs["pop3"] = { payload=b64(e.data) }
  submit(obs)
end

-- This function is called when a POP3 SSL message is observed.
module.pop3_ssl = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "pop3_ssl"
  obs["pop3_ssl"] = { payload=b64(e.data) }
  submit(obs)
end

-- This function is called when an SMTP command is observed.
module.smtp_command = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "smtp_command"
  obs["smtp_command"] = { command=e.command }
  submit(obs)
end

-- This function is called when an SMTP response is observed.
module.smtp_response = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "smtp_response"
  obs["smtp_response"] = { status=e.status, text=e.text }
  submit(obs)
end

-- This function is called when an SMTP response is observed.
module.smtp_data = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "smtp_data"
  obs["smtp_data"] = { from=e.from, to=e.to, body=e.data }
  submit(obs)
end

-- This function is called when a NTP timestamp message is observed.
module.ntp_timestamp_message = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "ntp_timestamp"
  obs["ntp_timestamp"] = { version=e.header.version, mode=e.header.mode }
  submit(obs)
end

-- This function is called when a NTP control message is observed.
module.ntp_control_message = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "ntp_control"
  obs["ntp_control"] = { version=e.header.version, mode=e.header.mode }
  submit(obs)
end

-- This function is called when an NTP private message is observed.
module.ntp_private_message = function(e)
  local obs = initialise_observation(e)
  obs["action"] = "ntp_private"
  obs["ntp_private"] = { version=e.header.version, mode=e.header.mode }
  submit(obs)
end

-- Return the table
return module

