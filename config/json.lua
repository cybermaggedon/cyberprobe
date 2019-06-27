--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file outputs events as JSON, one JSON event per lie.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

-- The table should contain functions.

-- Call the JSON functions for all observer functions.
observer.event = function(e)
  data = e.json
  print(data)
end

-- Return the table
return observer

