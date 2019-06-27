
local addr = require("util.addresses")

local str_to_hex = function(x)
  return "0x" .. x:gsub('.', function (c)
      return string.format('%02X', string.byte(c))
    end)
end

local mime = require("mime")
-- Base64 encoding
local b64 = function(x)
  local a, b = mime.b64(x)
  if (a == nil) then
    return ""
  end
  return a
end


-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

observer.describe = function(e, action)
  local device = e.device
  ctxt = e.context
  local s = addr.describe_address(e.context, true)
  local d = addr.describe_address(e.context, false)
  io.write(string.format("%s: %s -> %s. %s\n", device, s, d, action))
  io.write(string.format("    Time: %s\n", e.time))
  io.flush()
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(e)
  local a = string.format("ICMP (type %d, class %d)", e.type, e.code)
  observer.describe(e, a)
  io.write("\n")
  io.flush()
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(e)

  if e.header.qr == 0 then
    observer.describe(e, "DNS query")
  else
    observer.describe(e, "DNS response")
  end

  for key, value in pairs(e.queries) do
    io.write(string.format("    Query: name=%s, type=%s, class=%s\n", value.name, value.type, value.class))
  end

  for key, value in pairs(e.answers) do
    io.write(string.format("    Answer: name=%s, type=%s, class=%s", value.name, value.type, value.class))
    if value.rdaddress then
       io.write(string.format(" -> %s", value.rdaddress))
    end
    if value.rdname then
       io.write(string.format(" -> %s", value.rdname))
    end
    io.write("\n")
  end

  io.write("\n")
  io.flush()	

end

-- This function is called when an HTTP request is observed.
observer.http_request = function(e)
  local a = string.format("HTTP %s request", e.method)
  observer.describe(e, a)
  io.write(string.format("    URL %s\n", e.url))

  -- Write header
  print(e.header)
  for key, value in pairs(e.header) do
    io.write(string.format("    %s: %s\n", key, value))
  end

  io.write("\n")
  io.flush()

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(e)

  local a = string.format("HTTP response %s %s", e.code, e.status)
  observer.describe(e, a)
  io.write(string.format("    URL %s\n", e.url))

  local rev = e.context:get_reverse()

  -- Write header
  for key, value in pairs(e.header) do
    io.write(string.format("    %s: %s\n", key, value))	
  end

  io.write("\n")
  io.flush()

end

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.event = function(e)
  if e.action == "dns_message" then
    observer.dns_message(e)
  end
  if e.action == "icmp" then
    observer.icmp(e)
  end
  if e.action == "http_request" then
    observer.http_request(e)
  end
  if e.action == "http_response" then
    observer.http_response(e)
  end
end

-- Return the table
return observer

