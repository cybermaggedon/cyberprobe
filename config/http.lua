
local ltn12 = require("ltn12")
local http = require("socket.http")

local module = {}

-- Make an HTTP request
module.http_req = function(u, meth, reqbody)
  local r, c, rg
  r, c, rg = http.request {
    url = u;
    method = meth;
    headers = {["Content-Length"] = #reqbody};
    source = ltn12.source.string(reqbody);
  }
  return c
end

return module

