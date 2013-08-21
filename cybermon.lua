--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display a summary of all
-- observered events.  This should serve as a template.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- The table should contain functions.  We currently use: data, trigger,
-- trigger_down.

-- This function is called when a data transfer occurs.  Context information
-- is contained in 'context', and 'data' is a string, containing the packet
-- data.
observer.connection_data = function(context, data)

  -- Get the LIID
  local liid = cybermon.get_liid(context)

  -- This gets a (vaguely) human readable description of the source and
  -- destination protocol stacks.
  local src = cybermon.describe_src(context)
  local dest = cybermon.describe_dest(context)

  -- Write out the information on standard output.
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", src, dest))
  io.write("\n")

end

observer.connection_up = function(context)
end

observer.connection_down = function(context)
end

observer.unrecognised_datagram = function(context, data)

  -- Get the LIID
  local liid = cybermon.get_liid(context)

  -- This gets a (vaguely) human readable description of the source and
  -- destination protocol stacks.
  local src = cybermon.describe_src(context)
  local dest = cybermon.describe_dest(context)

  -- Write out the information on standard output.
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", src, dest))
  io.write("\n")

end

observer.icmp = observer.unrecognised_datagram

-- This function is called when a known attacker goes off the air
observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

observer.http_request = function(context, method, url, header, body)

  -- Get the LIID
  local liid = cybermon.get_liid(context)

  -- This gets a (vaguely) human readable description of the source and
  -- destination protocol stacks.
  local src = cybermon.describe_src(context)
  local dest = cybermon.describe_dest(context)

  -- Write out the information on standard output.
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", src, dest))
  io.write(string.format("  HTTP request %s %s\n", method, url))

  -- Write header
  for key, value in pairs(header) do
    io.write(string.format("  %s: %s\n", key, value))
  end

  io.write("\n")

end

observer.http_response = function(context, code, status, header, url, body)

  -- Get the LIID
  local liid = cybermon.get_liid(context)

  -- This gets a (vaguely) human readable description of the source and
  -- destination protocol stacks.
  local src = cybermon.describe_src(context)
  local dest = cybermon.describe_dest(context)

  -- Write out the information on standard output.
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", src, dest))
  io.write(string.format("  HTTP response %d %s\n", code, status))
  io.write(string.format("  Resource %s\n", url))

  -- Write header
  for key, value in pairs(header) do
    io.write(string.format("  %s: %s\n", key, value))
  end

  io.write("\n")

end

observer.dns_message = function(context, header, queries, answers, auth, add)

  -- Get the LIID
  local liid = cybermon.get_liid(context)

  -- This gets a (vaguely) human readable description of the source and
  -- destination protocol stacks.
  local src = cybermon.describe_src(context)
  local dest = cybermon.describe_dest(context)

  -- Write out the information on standard output.
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", src, dest))


  if header.qr == 0 then
    io.write(string.format("  DNS query id %d\n", header.id))
  else
    io.write(string.format("  DNS response id %d\n", header.id))
  end

  for key, value in pairs(queries) do
    io.write(string.format("    Query: %s\n", value.name))
  end
  
  for key, value in pairs(answers) do
    io.write(string.format("    Answer: %s", value.name))
    if value.rdaddress then
       io.write(string.format(" -> %s", value.rdaddress))
    end
    if value.rdname then
       io.write(string.format(" -> %s", value.rdname))
    end
    io.write("\n")
  end
  
  io.write("\n")

end

-- Return the table
return observer

