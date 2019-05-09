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
observer.trigger_up = function(e)
end

-- This function is called when an attacker goes off the air
observer.trigger_down = function(e)
end

-- This function is called when a stream-orientated connection is made
-- (e.g. TCP)
observer.connection_up = function(e)
end

-- This function is called when a stream-orientated connection is closed
observer.connection_down = function(e)
end

-- This function is called when a datagram is observed, but the protocol
-- is not recognised.
observer.unrecognised_datagram = function(e)
end

-- This function is called when stream data  is observed, but the protocol
-- is not recognised.
observer.unrecognised_stream = function(e)
end

-- This function is called when an ICMP message is observed.
observer.icmp = function(e)
end

-- This function is called when an IMAP message is observed.
observer.imap = function(e)
end

-- This function is called when an IMAP SSL message is observed.
observer.imap_ssl = function(e)
end

-- This function is called when a POP3 message is observed.
observer.pop3 = function(e)
end

-- This function is called when a POP3 SSL message is observed.
observer.pop3_ssl = function(e)
end

-- This function is called when an HTTP request is observed.
observer.http_request = function(e)
end

-- This function is called when an HTTP response is observed.
observer.http_response = function(e)
end

-- This function is called when a SIP request message is observed.
observer.sip_request = function(e)
end

-- This function is called when a SIP response message is observed.
observer.sip_response = function(e)
end

-- This function is called when a SIP SSL message is observed.
observer.sip_ssl = function(e)
end

-- This function is called when an SMTP command is observed.
observer.smtp_command = function(e)
end

-- This function is called when an SMTP response is observed.
observer.smtp_response = function(e)
end

-- This function is called when an SMTP response is observed.
observer.smtp_data = function(e)
end

-- This function is called when a DNS message is observed.
observer.dns_message = function(e)

  if e.header.qr == 0 and #e.queries == 1 and e.queries[1].name == "example.org"
    and e.queries[1].type == 1 and e.queries[1].class == 1 then

    -- Send a fake response

    -- Set query/response flag to 'response'
    e.header.qr = 1

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

    e.context:forge_dns_response(e.header, e.queries, answers, {}, {})

  end

end

-- This function is called when an FTP command is observed.
observer.ftp_command = function(e)
end

-- This function is called when an FTP response is observed.
observer.ftp_response = function(e)
end

-- This function is called when an NTP timestamp message is observed.
observer.ntp_timestamp_message = function(e)
end

-- This function is called when an NTP control message is observed.
observer.ntp_control_message = function(e)
end

-- This function is called when an NTP private message is observed.
observer.ntp_private_message = function(e)
end

-- This function is called when a gre message is observed.
observer.gre = function(e)
end

-- This function is called when a grep pptp message is observed.
observer.grep_pptp = function(e)
end

-- This function is called when an esp message is observed.
observer.esp = function(e)
end

-- This function is called when an unrecognised ip protocol message is observed.
observer.unrecognised_ip_protocol = function(e)
end

-- This function is called when an 802.11 message is observed.
observer.wlan = function(e)
end

-- Return the table
return observer

