--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with redis, so that network events are RPUSH'd
-- on a list to use as a queue.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local json = require("json")
local oauth2 = require("config.util.oauth2")
local os = require("os")
local https = require("ssl.https")
local string = require("string")
local model = require("util.json")
local socket = require("socket")

-- Config ------------------------------------------------------------------
local private = "private.json"
if os.getenv("PRIVATE") then
  private = os.getenv("PRIVATE")
end

local project = "INSERT_YOUR_PROJECT"
if os.getenv("PROJECT") then
  project = os.getenv("PROJECT")
end

local topic = "INSERT_YOUR_TOPIC"
if os.getenv("TOPIC") then
  topic = os.getenv("TOPIC")
end

-- Initialise.
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

-- Pubsub object submission function - just pushes the object onto the queue.
local submit = function(obs)
  local msgs = {}
  msgs[1] = { ["data"] = b64(json.encode(obs)) }
  local txt = json.encode({ ["messages"] = msgs })
  uri =
    string.format("https://pubsub.googleapis.com/v1/projects/%s/topics/%s:publish",
         project, topic)
  a, st, b, c = req(uri, "POST", txt, token)
  print(st)
  if not (st == 200) then
    print("Status: " .. st)
    print(c)
  end
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

-- Register Redis submission.
model.init(submit)

-- Initialise
init()

-- Return the table
return observer

