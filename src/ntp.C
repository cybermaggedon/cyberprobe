
#include <cybermon/ntp.h>
#include <cybermon/manager.h>
#include <cybermon/address.h>
#include <cybermon/udp.h>
#include <cybermon/ip.h>


using namespace cybermon;

namespace
{
    bool is_ntp_port(uint16_t port)
    {
        const uint16_t ntp_port = 123;
        return port == ntp_port;
    }
}

bool ntp::ident(uint16_t source_port,
	            uint16_t destination_port)
{
    return is_ntp_port(source_port) || 
           is_ntp_port(destination_port);
}


void ntp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    
    // Parse NTP.
    ntp_decoder dec(s, e);
    ntp_decoder::packet_type pt = dec.parse();
    if(pt == ntp_decoder::unknown_packet)
    {
        throw exception("Failed to parse NTP packet");
    }
    
    address src, dest;
    std::vector<unsigned char> empty;
    src.set(empty, APPLICATION, NTP);
    dest.set(empty, APPLICATION, NTP);

    flow_address f(src, dest);
    ntp_context::ptr fc = ntp_context::get_or_create(c, f);

    fc->lock.lock();

    try 
    {
        switch(pt)
        {
            case ntp_decoder::timestamp_packet:
                mgr.ntp_timestamp_message(fc, dec.get_timestamp_info());
                break;
                
            case ntp_decoder::control_packet:
                mgr.ntp_control_message(fc, dec.get_control_info());
                break;
                
            case ntp_decoder::private_packet:
                mgr.ntp_private_message(fc, dec.get_private_info());
                break;
                
            default:
                break;
        } 

    } 
    catch (std::exception& e) 
    {
        fc->lock.unlock();
        throw;
    }

    fc->lock.unlock();
}

