
local observer = {}

observer.data = function(context, data)
  liid = cybermon.get_liid(context)
  io.write(string.format("Target %s:\n", liid))
  io.write(string.format("  %s -> %s\n", cybermon.describe_src(context),
           cybermon.describe_dest(context)))
  io.write("\n")
end

observer.trigger = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

print("Configuration loaded")

return observer

