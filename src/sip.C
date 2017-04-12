
#include <cybermon/sip.h>

#include <boost/regex.hpp>

#include <string>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/rtp.h>
#include <cybermon/sip_context.h>
#include <cybermon/tcp_ports.h>
#include <cybermon/udp_ports.h>


using namespace cybermon;


void sip::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, SIP);
    dest.set(empty, APPLICATION, SIP);

    flow_address f(src, dest);

    sip_context::ptr fc = sip_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Regex strips the request from the header fields (which follow after the CRLF)
    static const boost::regex sip_request("^(REGISTER|INVITE|ACK|CANCEL|OPTIONS|BYE|REFER|NOTIFY|MESSAGE|SUBSCRIBE|INFO) "
                                            "(sips?:[^ ]*) SIP/[0-9]\\.[0-9]\r\n(.*$)", boost::regex::extended);
    
    // Regex strips the response from the header fields (which follow after the CRLF)
    static const boost::regex sip_response("^SIP/[0-9]\\.[0-9] ([0-9]+) ([^\r\n]*)\r\n(.*$)", boost::regex::extended);


    std::string ident_buffer;

    // Copy into the ident buffer.
    ident_buffer.insert(ident_buffer.end(), s, e);

    boost::match_results<std::string::const_iterator> what;

    if (regex_search(ident_buffer, what, sip_request, boost::match_continuous))
    {
        // Groups are: 
        // 1. Method
        // 2. Request-URI
        // 3. Header fields

        fc->method = what[1];

        // Ignore what[2] and extract 'from' (and 'to') out of the Header fields

        // Parse the Header fields
        fc->parse(what[3]);

        // Only the INVITE contains the RTP port numbers
        if (fc->method.compare("INVITE")==0)
        {
            // This is only a first stab at the functionality needed to link the SIP 
            // channels and their associated RTP streams. Right now the port number is 
            // identified and a handler assigned but a state model is needed to reflect
            // the state of the call so handler(s) are added/removed as the call 
            // begins/ends. Probably need to differentiate between TCP from UDP too.
            
            
            // Assign an RTP handler if the audio port is specified
            if (fc->audio_port != 0)
            {
                tcp_ports::add_port_handler(fc->audio_port, &rtp::process);
                udp_ports::add_port_handler(fc->audio_port, &rtp::process);
            }

            // Assign an RTP handler if the video port is specified
            if (fc->video_port != 0)
            {
                tcp_ports::add_port_handler(fc->video_port, &rtp::process);
                udp_ports::add_port_handler(fc->video_port, &rtp::process);
            }
        }

        // Send message with arguments: method, from & to
        mgr.sip_request(fc, fc->method, fc->from, fc->to, s, e);
        return;
    }
    else if (regex_search(ident_buffer, what, sip_response, boost::match_continuous))
    {
        // Groups are: 
        // 1. Code
        // 2. Status
        // 3. Header fields

        fc->parse(what[3]);

        // Convert the code into a int - nasty!
        int codeval;
        std::istringstream buf(what[1]);
        buf >> codeval;

        // Send message with arguments: code, status, from & to
        mgr.sip_response(fc, codeval, what[2], fc->from, fc->to, s, e);
        return;
    }
    else
    {
        throw exception("Unexpected SIP message");
    }
}

