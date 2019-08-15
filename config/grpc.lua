
local os = require("os")

local server = "localhost:50051"

if os.getenv("GRPC_SERVICE") then
  server = os.getenv("GRPC_SERVICE")
end

observer = {}

observer.event = function(e)
  grpc:observe(e, server)
end

return observer

