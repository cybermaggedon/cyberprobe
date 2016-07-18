
json = require("json")
crypt = require("crypto")
os = require("os")
mime = require("mime")
local ltn12 = require("ltn12")
local http = require("socket.http")
local https = require("ssl.https")
local url = require("socket.url")

local f = assert(io.open("private.json", "r"))
local data = json.decode(f:read("*all"))

email = data["client_email"]
private = data["private_key"]

param = function(tbl)
  local tuples
  do
    local _accum_0 = { }
    local _len_0 = 1
    for k, v in pairs(tbl) do
      _accum_0[_len_0] = tostring(url.escape(k)) .. "=" .. tostring(url.escape(v))
      _len_0 = _len_0 + 1
    end
    tuples = _accum_0
  end
  return table.concat(tuples, "&")
end

-- Make an HTTP request
req = function(u, meth, reqbody, ct)
  local r, c, rg, s
  res = https.request {
    url = u;
    method = meth;
    headers = {["Content-Length"] = #reqbody, ["Content-Type"] = ct};
    source = ltn12.source.string(reqbody);
  }
  return res
end

-- Make an HTTP request
req = function(u, meth, reqbody, content_type)
  local r, c, rg
  local t = {}
  r, c, rg = https.request {
    url = u;
    method = meth;
    headers = {["Content-Length"] = #reqbody, ["Content-Type"] = content_type};
    source = ltn12.source.string(reqbody);
    sink = ltn12.sink.table(t)
  }
  return r, c, rg, table.concat(t)
end

local b64 = function(x)
  local a, b = mime.b64(x)
  if (a == nil) then
    return ""
  end
  a = a:gsub("/", "_")
  a = a:gsub("%+", "-")
  return a
end

header = {alg = "RS256", typ = "JWT"}
header = json.encode(header)
header = b64(header)

cs = {
    iss = email,
    scope = "https://www.googleapis.com/auth/cloud-platform",
    aud = "https://www.googleapis.com/oauth2/v4/token",
    exp = os.time() + 120,
    iat = os.time()
    }
cs = json.encode(cs)
cs = b64(cs)

sig_input = header .. "." .. cs

private = crypto.pkey.from_pem(private, true)

sig = mime.b64(crypto.sign("sha256WithRSAEncryption", sig_input, private))

jwt = header .. "." .. cs .. "." .. sig

params = {
  grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer",
  assertion = jwt
  }
params = param(params)

uri = "https://www.googleapis.com/oauth2/v4/token"

a, b, c, d = req(uri, "POST", params, "application/x-www-form-urlencoded")

print(a)
print(b)
print(c)
print(d)
