--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file configures cybermon to dump all captured data to
-- datadump.* files.
--

local observer = {}

local seen = {}

-- This isn't particular efficient - it keeps opening and closing files.
observer.data = function(context, data)
  liid = cybermon.get_liid(context)
  id = cybermon.get_context_id(context)

  local fd

  local path = "datadump." .. id

  if seen[id] then
    fd = io.open(path, "a")
    io.write("Appending to " .. path .. "\n")
  else
    fd = io.open(path, "w")
    fd:write("Target %s\n", liid)
    fd:write(string.format("  %s -> %s\n\n", cybermon.describe_src(context),
             cybermon.describe_dest(context)))
    seen[id] = true
    io.write(string.format("Created file %s\n", path))
  end

  fd:write(data)

  fd:close()

end

observer.trigger_up = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

observer.trigger_down = function(liid)
  io.write(string.format("Target %s gone off air\n\n", liid))
end

print("Configuration loaded")

return observer

