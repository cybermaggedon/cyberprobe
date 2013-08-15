--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to display a summary and
-- hexdump of all observed data.
--

local observer = {}

observer.hexdump =  function(buf)
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


observer.data = function(context, data)
  liid = cybermon.get_liid(context)
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", cybermon.describe_src(context),
           cybermon.describe_dest(context)))
  observer.hexdump(data:sub(1, 16 * 8))
  io.write("\n")
end

observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

observer.trigger_down = function(liid, addr)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

print("Configuration loaded")

return observer

