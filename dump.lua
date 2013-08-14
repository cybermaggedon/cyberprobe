
local observer = {}

observer.seen = {}

observer.data = function(context, data)
  liid = cybermon.get_liid(context)
  id = cybermon.get_context_id(context)

  local fd

  local path = "data/" .. id

  if observer.seen[id] then
    fd = io.open(path, "a")
    io.write("Appending to " .. path .. "\n")
  else
    fd = io.open(path, "w")
    fd:write("Target %s\n", liid)
    fd:write(string.format("  %s -> %s\n\n", cybermon.describe_src(context),
             cybermon.describe_dest(context)))
    observer.seen[id] = true
    io.write(string.format("Created file %s\n", path))
  end

  fd:write(data)

  fd:close()

end

observer.trigger = function(liid, addr)
  io.write(string.format("Target %s detected at address %s\n\n", liid, addr))
end

print("Configuration loaded")

return observer

