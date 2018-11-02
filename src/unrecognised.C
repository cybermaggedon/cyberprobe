
#include <cybermon/unrecognised.h>
#include <cybermon/manager.h>
#include <cybermon/tcp.h>

using namespace cybermon;

void unrecognised::process_unrecognised_stream(manager& mgr, context_ptr c, 
					       const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, UNRECOGNISED);
    dest.set(empty, TRANSPORT, UNRECOGNISED);

    flow_address f(src, dest, sl.direc);

    unrecognised_stream_context::ptr fc = 
	unrecognised_stream_context::get_or_create(c, f);

    fc->lock.lock();

    try {
        mgr.unrecognised_stream(fc, sl.start, sl.end, sl.time, fc->position);
        fc->position += sl.end - sl.start;
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw;
    }

    fc->lock.unlock();

}


void unrecognised::process_unrecognised_datagram(manager& mgr, context_ptr c, 
						 const pdu_slice& sl)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, UNRECOGNISED);
    dest.set(empty, TRANSPORT, UNRECOGNISED);

    flow_address f(src, dest, sl.direc);

    unrecognised_datagram_context::ptr fc = 
	unrecognised_datagram_context::get_or_create(c, f);

    fc->lock.lock();

    try {
        mgr.unrecognised_datagram(fc, sl.start, sl.end, sl.time);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw;
    }

    fc->lock.unlock();

}

