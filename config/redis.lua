--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with redis, so that network events are RPUSH'd
-- on a list to use as a queue.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local redis = require("redis")
local os = require("os")
local string = require("string")
local socket = require("socket")

-- Config ------------------------------------------------------------------

local redist_host = "localhost"
local redis_port = 6379

if os.getenv("REDIS_SERVER") then
  local redis_server = os.getenv("REDIS_SERVER")
  local a, b = string.find(redis_server, ":")
  if a > 0 then
    redis_host = string.sub(redis_server, 1, a-1)
    redis_port = tonumber(string.sub(redis_server, b + 1, -1))
  end

  if os.getenv("QUEUE") then
    queue = os.getenv("QUEUE")
  else
    queue = 'input'
  end
  
end

-- Initialise.
local init = function()
  while true do
    if pcall(function() client = redis.connect(redis_host, redis_port) end ) then
      break
    else
      print("Redis connection failed, will retry...")
      socket.select(nil, nil, 5)
    end
  end
  print("Connected to redis.")
end

-- Redis object submission function - just pushes the object onto the queue.
local submit = function(obs)
  while true do
    if pcall(function() client:rpush(queue, obs) end) then
      break
    end
    print("Redis delivery failed, will reconnect.")
    -- Failed, so reconnect and retry...
    init()
  end
end

-- Call the JSON functions for all observer functions.
observer.event = function(e)
  submit(e:json())
end

-- Initialise
init()

-- Return the table
return observer

