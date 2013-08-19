--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display a summary and
-- hexdump of all observed data.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- The table should contain functions.  We currently use: data, trigger,
-- trigger_down.

-- Local function, does a hexdump.
local hexdump =  function(buf)
  for i=1, math.ceil(#buf/16) * 16 do
    if (i-1) % 16 == 0 then io.write(string.format('  %08X  ', i-1)) end
    io.write( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
    if i %  8 == 0 then io.write(' ') end
    if i % 16 == 0 then
      local s = buf:sub(i-16+1, i)
      for j = 1, #s do
        if s:byte(j) >= 32 and s:byte(j) <= 126 then
          io.write(s:sub(j,j))
  	else
	  io.write(".")
	end
      end
      io.write('\n')
    end
  end
end

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

  -- Write a hexdump.
  hexdump(data)
  io.write("\n")
end

observer.connection_up = function(context)
  liid = cybermon.get_liid(context)
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", cybermon.describe_src(context),
           cybermon.describe_dest(context)))
  io.write("  Connected.\n\n");
end

observer.connection_down = function(context)
  liid = cybermon.get_liid(context)
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", cybermon.describe_src(context),
           cybermon.describe_dest(context)))
  io.write("  Disconnected.\n\n");
end

observer.datagram = observer.connection_data

-- This function is called when the address of an attacker has been
-- identified.
observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

-- This function is called when a known attacker goes off the air
observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

observer.http_request = function(context, method, url, body)

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
  hexdump(body)
  io.write("\n")

end

observer.http_response = function(context, code, status, body)

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
  hexdump(body)
  io.write("\n")

end

return observer

