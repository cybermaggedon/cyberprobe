--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with Google pub/sub, so that network events are
-- presented as pub/sub events.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------

local mime = require("mime")
local jsenc = require("json.encode")
local oauth2 = require("config.util.oauth2")
local https = require("ssl.https")
local addr = require("util.addresses")

-- Config ------------------------------------------------------------------
local private = "private.json"
local project = "INSERT-PROJECT-NAME"
local topic = "INSERT-TOPIC-NAME"

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

-- Make an HTTP request
local req = function(u, meth, reqbody, auth)
  local r, c, rg
  local t = {}
  r, c, rg = https.request {
    url = u;
    method = meth;
    headers = {["Content-Length"] = #reqbody, ["Authorization"] = auth};
    source = ltn12.source.string(reqbody);
    sink = ltn12.sink.table(t)
  }
  return r, c, rg, table.concat(t)
end

local token = nil
local bearer = nil
local expiry = 0

-- Initialise.  This gets a token from Google OAUTH2.
local init = function()

  print("Get auth token...")
  token, expiry = oauth2.get_token(private)

  print("Create topic...")
  local uri =
    string.format("https://pubsub.googleapis.com/v1/projects/%s/topics/%s",
                  project, topic)
  a, st, c, b = req(uri, "PUT", "", token)
  if not(st == 200) and not(st == 409) then
    print("Status: " .. st)
    print(b)
    os.exit(0)
  end

end

-- Initialise a basic observation
local initialise_observation = function(context, indicators)

  local obs = {}
  obs["liid"] = context:get_liid()
  obs["src"] = addr.get_stack(context, true)
  obs["dest"] = addr.get_stack(context, false)

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

  return obs

end

local submit_observation = function(obs)
  local txt = json.encode(obs)
  print(txt)
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
  local obs = initialise_observation(context)
  obs["action"] = "connected_up"
  submit_observation(obs)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  local obs = initialise_observation(context)
  obs["action"] = "connected_down"
  submit_observation(obs)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "unrecognised_datagram"
  obs["data"] = b64(data)
  submit_observation(obs)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "unrecognised_stream"
  obs["data"] = b64(data)
  submit_observation(obs)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local obs = initialise_observation(context)
  obs["action"] = "icmp"
  obs["data"] = b64(data)
  submit_observation(obs)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
  local obs = initialise_observation(context)
  obs["action"] = "http_request"
  obs["method"] = method
  obs["url"] = url
  obs["header"] = header
  obs["body"] = b64(body)
  submit_observation(obs)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
  local obs = initialise_observation(context)
  obs["action"] = "http_response"
  obs["code"] = code
  obs["status"] = status
  obs["header"] = header
  obs["url"] = url
  obs["body"] = b64(body)
  submit_observation(obs)
end


-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)
  local obs = initialise_observation(context)

  obs["action"] = "dns_message"

  if header.qr == 0 then
    obs["type"] = "query"
  else
    obs["type"] = "response"
  end

  local q = {}
  for key, value in pairs(queries) do
    q[#q + 1] = value.name
  end
  obs["queries"] = q

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
  obs["answers"] = q
  submit_observation(obs)

end


-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
  local obs = initialise_observation(context)
  obs["action"] = "ftp_command"
  obs["command"] = command
  submit_observation(obs)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
  local obs = initialise_observation(context)
  obs["action"] = "ftp_response"
  obs["status"] = status
  obs["text"] = text
  submit_observation(obs)
end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)
  local obs = initialise_observation(context)
  obs["action"] = "smtp_command"
  obs["command"] = command
  submit_observation(obs)
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)
  local obs = initialise_observation(context)
  obs["action"] = "smtp_response"
  obs["status"] = status
  obs["text"] = text
  submit_observation(obs)
end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)
  local obs = initialise_observation(context)
  obs["action"] = "smtp_data"
  obs["from"] = from
  obs["to"] = to
  obs["data"] = data
  submit_observation(obs)
end

-- Initialise
init()

-- Return the table
return observer

