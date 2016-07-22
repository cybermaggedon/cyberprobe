
lzmq = require("lzmq")
json = require("json")

context = lzmq.context()
skt = context:socket(lzmq.SUB)

skt:connect("tcp://localhost:5555")
skt:subscribe("")

while true do
  msg, rtn = skt:recv()
  msg = json.decode(msg)

  print("ID: <FIXME>")
  
  if msg["action"] then
    print("Action: " .. msg["action"])
  end
  
  if msg["device"] then
    print("Device: " .. msg["device"])
  end
   
  if msg["time"] then
    print("Time: " .. msg["time"])
  end
  
  if msg["method"] then
    print("Method: " .. msg["method"])
  end
  
  if msg["url"] then
    print("URL: " .. msg["url"])
  end
  
  if msg["command"] then
    print("Command: " .. msg["command"])
  end
  
  if msg["status"] then
    print("Status: " .. msg["status"])
  end
  
  if msg["text"] then
    for k, v in ipairs(msg["text"]) do
      print("Text: " .. v)
    end
  end
  
  if msg["payload"] then
    print("Payload: <not shown>")
  end
  
  if msg["from"] then
    print("From: " .. msg["from"])
  end
  
  if msg["to"] then
    for k, v in ipairs(msg["to"]) do
      print("To: " .. v)
    end
  end
  
  if msg["body"] then
    print("body: <not shown>")
  end

  if msg["header"] then
    for k, v in pairs(msg["header"]) do
      print("HTTP " .. k .. " header: " .. v)
    end
  end

  if msg["type"] then
    print("Type: " .. msg["type"])
  end
    
  if msg["queries"] then
    for k, v in ipairs(msg["queries"]) do
      print("Query: " .. v)
    end
  end
    
  if msg["answers"] then
    for k, v in ipairs(msg["answers"]) do
      if v["name"] then
        print("Answer name: " .. v["name"])
      end
      if v["address"] then
        print("Answer address: " .. v["address"])
      end
    end
  end

  if msg["src"] then
    for k, v in ipairs(msg["src"]) do
      print("Source: " .. v)
    end
  end
    
  if msg["dest"] then
    for k, v in ipairs(msg["dest"]) do
      print("Dest: " .. v)
    end
  end
    
  print("")
end

