
#include <cybermon/ntp.h>
#include <cybermon/manager.h>
#include <cybermon/address.h>
#include <cybermon/udp.h>
#include <cybermon/ip.h>


using namespace cybermon;

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
    src.set({}, APPLICATION, NTP);
    dest.set({}, APPLICATION, NTP);

    flow_address f(src, dest);
    ntp_context::ptr fc = ntp_context::get_or_create(c, f);

    fc->lock.lock();

    try 
    {
        switch(pt)
        {
            case ntp_decoder::timestamp_packet:
                mgr.ntp_timestamp_message(fc, dec.timestamp_info);
                break;
                
            case ntp_decoder::control_packet:
                mgr.ntp_control_message(fc, dec.control_info);
                break;
                
            case ntp_decoder::private_packet:
                mgr.ntp_private_message(fc, dec.private_info);
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

