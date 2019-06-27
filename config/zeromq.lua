--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with zeromq pub/sub, so that network events are
-- presented as pub/sub events.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local lzmq = require("lzmq")
local os = require("os")

-- Config ------------------------------------------------------------------

--
-- To offer a local publication port: either just do nothing, and accept
-- the default 5555 port, or set ZMQ_BINDING to something like tcp://*:12345
-- to specify the port number.  To push to a remote port, 
local binding
local connection
if os.getenv("ZMQ_BINDING") then
  binding = os.getenv("ZMQ_BINDING")
else
  if os.getenv("ZMQ_CONNECT") then
    connection = os.getenv("ZMQ_CONNECT")
  else
    binding = "tcp://*:5555"
  end
end

-- Local socket state
local context
local skt

-- Initialise.
local init = function()

  context = lzmq.context()

  if binding then
    skt = context:socket(lzmq.PUB)
    ret = skt:bind(binding)

    if ret == false then
      print("ZeroMQ bind failed")
      os.exit(1)
    end
  else
     skt = context:socket(lzmq.PUSH)
     ret = skt:connect(connection)

     if ret == false then
       print("ZeroMQ connect failed")
       os.exit(1)
    end
 end

end

-- ZeroMQ object submission function - just pushes the object onto the queue.
local submit = function(obs)
  ret = skt:send(obs)
end

-- Call the JSON functions for all observer functions.
observer.event = function(e)
  submit(e.json)
end

-- Initialise
init()

-- Return the table
return observer

