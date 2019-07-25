--
-- Cybermon configuration file, used to tailor the behaviour of cybermon.
--
-- This configuration file does nothing.  The event functions are all empty
-- stubs.  Maybe a good starting point for building your own config from
-- scratch.
--

-- This file is a module, so you need to create a table, which will be
-- returned to the calling environment.  It doesn't matter what you call it.
local observer = {}

observer.event = function(e)
  if e.action ~= "dns_message" then
    return
  end

  if e.header.qr == 0 and #e.queries == 1 and e.queries[1].name == "example.org"
    and e.queries[1].type == 1 and e.queries[1].class == 1 then

    -- Send a fake response

    -- Set query/response flag to 'response'
    header = e.header
    header.qr = 1
    header.ancount = 2

    -- Two answers, give example.org 2 alternative IP addresses.
    answers = {}
    answers[1] = {}
    answers[1].name = "example.org"
    answers[1].type = 1
    answers[1].class = 1
    answers[1].rdaddress = "1.2.3.4"
    answers[2] = {}
    answers[2].name = "example.org"
    answers[2].type = 1
    answers[2].class = 1
    answers[2].rdaddress = "5.6.7.8"

    -- Two answers
    e.header.ancount = 2

    io.write("Forging DNS response!\n")

    e.context:forge_dns_response(header, e.queries, answers, {}, {})

  end

end

-- Return the table
return observer

