--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file stores events in ElasticSearch.  The event
-- functions are passed through to util/json.lua which will format an
-- entry for elasticsearch (except for dns_messages which are handled
-- locally to esure they are searchable)
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

local elastic = require("util.elastic")
local model = require("util.json")
local json = require("json")
local dns = require("util.dns")

elastic.init()

-- elastic search object submission function
local submit = function(obs)
  ret = elastic.submit_observation(obs)
end

-- Call the JSON functions for observer functions (except for dns)
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
observer.ftp_command = model.ftp_command
observer.ftp_response = model.ftp_response
observer.ntp_timestamp_message = model.ntp_timestamp_message
observer.ntp_control_message = model.ntp_control_message
observer.ntp_private_message = model.ntp_private_message


-- special dns handling method to allow json to be searchable
observer.dns_message = function(e)

  local obs = model.initialise_observation(e)

  obs["action"] = "dns_message"
  obs["dns"] = {}

  if e.header.qr == 0 then
    obs["dns"]["type"] = "query"
  else
    obs["dns"]["type"] = "response"
  end

  local q = {}
  local names = {}
  json.util.InitArray(names)
  local types = {}
  json.util.InitArray(types)
  local classes = {}
  json.util.InitArray(classes)
  for key, value in pairs(e.queries) do
    names[#names + 1] = value.name
    if dns.type_name[value.type] == nil then
      types[#types + 1] = tostring(value.type)
    else
      types[#types + 1] = dns.type_name[value.type]
    end
    classes[#classes + 1] = dns.class_name[value.class]
  end
  q["name"] = names
  q["type"] = types
  q["class"] = classes
  obs["dns"]["query"] = q

  local q = {}
  local names = {}
  json.util.InitArray(names)
  local types = {}
  json.util.InitArray(types)
  local classes = {}
  json.util.InitArray(classes)
  local addresses = {}
  json.util.InitArray(addresses)
  for key, value in pairs(e.answers) do
    names[#names + 1] = value.name
    if dns.type_name[value.type] == nil then
      types[#types + 1] = tostring(value.type)
    else
      types[#types + 1] = dns.type_name[value.type]
    end
    classes[#classes + 1] = dns.class_name[value.class]
    if value.rdaddress then
       addresses[#addresses + 1] = value.rdaddress
    end
    if value.rdname then
       names[#names] = value.rdname
    end
  end
  q["name"] = names
  q["type"] = types
  q["class"] = classes
  q["address"] = addresses
  obs["dns"]["answer"] = q
  
  submit(obs)

end

-- Register elastic submission.
model.init(submit)


-- Return the table
return observer

