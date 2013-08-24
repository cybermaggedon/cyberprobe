--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display a summary of all
-- observered events.  This can serve as a template.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- Says whether we've seen contexts before.
local seen = {}

-- The table should contain functions.

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

-- Used to recurse up the protocol stack and get protocol addresses as a
-- string.  context=protocol context, is_src=true to study source addresses,
-- otherwise it returns destination address stack.
observer.describe_address = function(context, is_src)
  local par = context:get_parent()
  local str = ""
  if par then
    if is_src then
      str = observer.describe_address(par, true)
    else
      str = observer.describe_address(par, false)
    end
  end
  local cls, addr
  if is_src then
    cls, addr = context:get_src_addr()
  else
    cls, addr = context:get_dest_addr()
  end
  if not(addr == "") then
    if not(str == "") then
      str = str .. ":"
    end
    str = str .. addr
  end
  return str
end

observer.get_fd = function(context, action)

  local id = context:get_context_id(context)
  local fd
  local path = "data/dump." .. id

  if seen[id] then
    fd = io.open(path, "a")
    io.write("Appending to " .. path .. "\n")
  else
    fd = io.open(path, "w")
    local liid = context:get_liid()
    local s = observer.describe_address(context, true)
    local d = observer.describe_address(context, false)
    fd:write(string.format("%s: %s -> %s. %s\n", liid, s, d, action))
    seen[id] = true
    io.write(string.format("Created file %s\n", path))
  end

  return fd

end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(context)
  --observer.describe(context, "Connected")
  --io.write("\n")
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
  --observer.describe(context, "Disconnected")
  --io.write("\n")
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
  local a = string.format("Datagram (size is %d)", #data)
  local fd = observer.get_fd(context, a)
  fd:write(data)
  fd:close()
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
  local a = string.format("Stream data (size is %d)", #data)
  local fd = observer.get_fd(context, a)
  fd:write(data)
  fd:close()
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, data)
  local a = string.format("ICMP (size is %d)", #data)
  local fd = observer.get_fd(context, a)
  fd:write(data)
  fd:close()
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)

  local a = string.format("HTTP %s request", method)
  local fd = observer.get_fd(context, a)

  fd:write(string.format("URL %s\n", url))

  -- Write header
  for key, value in pairs(header) do
    fd:write(string.format("%s: %s\n", key, value))
  end

  fd:write(body)
  fd:close()

end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)

  local a = string.format("HTTP response %s %s", code, status)
  local fd = observer.get_fd(context, a)

  fd:write(string.format("URL %s\n", url))

  -- Write header
  for key, value in pairs(header) do
    fd:write(string.format("%s: %s\n", key, value))
  end

  fd:write(body)
  fd:close()

end

-- This function is called when a DNS message is observed.
observer.dns_message = function(context, header, queries, answers, auth, add)

  local action

  if header.qr == 0 then
    action = "DNS query"
  else
    action = "DNS response"
  end

  local fd = observer.get_fd(context, action)

  for key, value in pairs(queries) do
    fd:write(string.format("Query: %s\n", value.name))
  end
  
  for key, value in pairs(answers) do
    fd:write(string.format("Answer: %s", value.name))
    if value.rdaddress then
       fd:write(string.format(" -> %s", value.rdaddress))
    end
    if value.rdname then
       fd:write(string.format(" -> %s", value.rdname))
    end
    fd:write("\n")
  end

  fd:close()

end

-- Return the table
return observer

