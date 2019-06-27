
#include <cybermon/ntp.h>
#include <cybermon/manager.h>
#include <cybermon/address.h>
#include <cybermon/udp.h>
#include <cybermon/ip.h>
#include <cybermon/event_implementations.h>


using namespace cybermon;


void ntp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;
    
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

    flow_address f(src, dest, sl.direc);
    ntp_context::ptr fc = ntp_context::get_or_create(c, f);

    fc->lock.lock();

    std::shared_ptr<event::event> ev;
    try 
    {
        switch(pt)
        {

            case ntp_decoder::timestamp_packet:
		ev =
		    std::make_shared<event::ntp_timestamp_message>(fc,
								   dec.get_timestamp_info(),
								   sl.time);
		mgr.handle(ev);
                break;
                
            case ntp_decoder::control_packet:
		ev =
		    std::make_shared<event::ntp_control_message>(fc,
								 dec.get_control_info(),
								 sl.time);
		mgr.handle(ev);
                break;
                
            case ntp_decoder::private_packet:
		ev =
		    std::make_shared<event::ntp_private_message>(fc,
								 dec.get_private_info(),
								 sl.time);
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

