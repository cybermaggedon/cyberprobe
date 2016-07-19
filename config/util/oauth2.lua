
local json = require("json")
local crypt = require("crypto")
local os = require("os")
local mime = require("mime")
local ltn12 = require("ltn12")
local http = require("socket.http")
local https = require("ssl.https")
local url = require("socket.url")

local module = {}

local url_params = function(tbl)
  local t = { }
  for k, v in pairs(tbl) do
    t[#t+1] = tostring(url.escape(k)) .. "=" .. tostring(url.escape(v))
  end
  return table.concat(t, "&")
end

-- Make an HTTP request
local req = function(u, meth, reqbody, content_type)
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

-- Base64 encode, url-safe encoding
local b64 = function(x)
  local a, b = mime.b64(x)
  if (a == nil) then
    return ""
  end
  a = a:gsub("/", "_")
  a = a:gsub("%+", "-")
  return a
end

module.get_token = function(file)

  -- Read key file
  local f = assert(io.open(file, "r"))
  local data = json.decode(f:read("*all"))
  local email = data["client_email"]
  local private = data["private_key"]

  -- Extract key from PEM data
  private = crypto.pkey.from_pem(private, true)

  -- JWT header
  local header = {alg = "RS256", typ = "JWT"}
  header = json.encode(header)
  header = b64(header)

  local now = os.time()

  -- JWT claim set
  local cs = {
    iss = email,
    scope = "https://www.googleapis.com/auth/cloud-platform",
    aud = "https://www.googleapis.com/oauth2/v4/token",
    exp = now + 3600,
    iat = now
  }
  cs = json.encode(cs)
  cs = b64(cs)

  -- Input to signature algorithm
  local sig_input = header .. "." .. cs

  -- Sign input using private key
  local sig = mime.b64(crypto.sign("sha256WithRSAEncryption", sig_input,
                       private))

  -- Construct JWT: header, claimset and signature.
  local jwt = header .. "." .. cs .. "." .. sig

  -- Construct params to OAUTH2 service.
  local params = {
    grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion = jwt
  }
  params = url_params(params)

  uri = "https://www.googleapis.com/oauth2/v4/token"

  a, st, c, b = req(uri, "POST", params, "application/x-www-form-urlencoded")

  if not st == 200 then
    print("OAUTH2 request failed")
    os.exit()
  end

  data = json.decode(b)

  if data["error"] then
    print(data["error_description"])
    os.exit()
  end

  token = data["token_type"] .. " ".. data["access_token"]
  return token, now + data["expires_in"]

end

return module

