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

-- The table should contain functions.

-- This function is called when a trigger events starts collection of an
-- attacker. liid=the trigger ID, addr=trigger address
observer.trigger_up = function(liid, addr)
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(liid)
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(context)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(context)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(context, data)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(context, data)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(context, icmp_type, icmp_code, data)
end

-- This function is called when an IMAP message is observed.
observer.imap = function(context, data)
end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(context, data)
end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(context, data)
end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(context, data)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(context, method, url, header, body)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(context, code, status, header, url, body)
end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(context, command)
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(context, status, text)
end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(context, from, to, data)
end

-- This function is called when a DNS over_TCP message is observed.
observer.dns_over_tcp_message = function(context, header, queries, answers, auth, add)
end

-- This function is called when a DNS over UDP message is observed.
observer.dns_over_udp_message = function(context, header, queries, answers, auth, add)

  if header.qr == 0 and #queries == 1 and queries[1].name == "example.org"
    and queries[1].type == 1 and queries[1].class == 1 then

    -- Send a fake response

    -- Set query/response flag to 'response'
    header.qr = 1

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
    header.ancount = 2

    io.write("Forging DNS response!\n")

    context:forge_dns_response(header, queries, answers, {}, {})

  end

end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(context, command)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(context, status, text)
end

-- Return the table
return observer

