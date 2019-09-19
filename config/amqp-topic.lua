--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
-- This one integrates cybermon with an AMQP broker, so that network events are
-- published to an exchange.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Other modules -----------------------------------------------------------
local amqp = require("amqp")
local os = require("os")
local string = require("string")
local socket = require("socket")

-- Config ------------------------------------------------------------------

local default_broker = "localhost:5672"
if os.getenv("AMQP_BROKER") then
  broker = os.getenv("AMQP_BROKER")
else
  broker = default_broker
end
local broker_host = broker
local broker_port = 5672
local a, b = string.find(broker, ":")
if a then
  broker_host = string.sub(broker, 1, a-1)
  broker_port = tonumber(string.sub(broker, b + 1, -1))
end

if os.getenv("AMQP_EXCHANGE") then
  exch = os.getenv("AMQP_EXCHANGE")
else
  exch = 'amq.topic'
end

if os.getenv("AMQP_ROUTING_KEY") then
  rkey = os.getenv("AMQP_ROUTING_KEY")
else
  rkey = 'cyberprobe'
end

print("Broker: " .. broker_host .. ":" .. tostring(broker_port))
print("Exchange: " .. exch)
print("Routing key: " .. rkey)

-- Initialise.
local init = function()

  while true do

    if not pcall(function() ctx = amqp.new({role = "publisher", exchange = exch, routing_key = rkey}) end) then
 
      print("AMQP connection failed, will retry...")
      socket.select(nil, nil, 5)

    else

      ok = ctx:connect(broker_host, broker_port)

      if not ok then
        print("AMQP connection failed, will retry...")
        ctx:close()
        socket.select(nil, nil, 5)
      else

       ok = ctx:setup()

       if not ok then
	 print("AMQP setup failed, will retry...")
	 ctx:close()
	 socket.select(nil, nil, 5)

       else

	 print("AMQP connection created.")
	 return

	end

      end

    end

  end

end

-- Object submission function - just pushes the object onto the queue.
local submit = function(obs)
  while true do
    local ok, err = ctx:publish(obs)
    if not ok then
      ctx:close()
      print("AMQP delivery failed, will reconnect.")
      socket.select(nil, nil, 5)
      init()
    else
      return
    end
  end
end

observer.event = function(e)
  data = e:json()
  submit(data)
end

-- Initialise
init()

-- Return the table
return observer

