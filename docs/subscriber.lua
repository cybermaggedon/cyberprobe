
lzmq = require("lzmq")

context = lzmq.context()
skt = context:socket(lzmq.SUB)

skt:connect("tcp://localhost:5555")
skt:subscribe("")

while true do
  msg, rtn = skt:recv()
  print(msg)
end

