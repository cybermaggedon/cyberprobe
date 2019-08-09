--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file outputs events as JSON, one JSON event per lie.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- The table should contain functions.

mime = require("mime")

-- Call the JSON functions for all observer functions.
observer.event = function(e)

  -- This isn't usable yet.
  data = e:protobuf()
  enc = mime.b64(data)
  print(enc)
end

-- Return the table
return observer

