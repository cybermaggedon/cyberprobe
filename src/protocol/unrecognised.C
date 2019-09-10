
#include <memory>

#include <cyberprobe/protocol/unrecognised.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/tcp.h>
#include <cyberprobe/event/event_implementations.h>

using namespace cyberprobe::protocol;

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

    std::lock_guard<std::mutex> lock(fc->mutex);

    auto ev =
	std::make_shared<event::unrecognised_stream>(fc, sl.start, sl.end,
						     sl.time,
						     fc->position);
    mgr.handle(ev);
    fc->position += sl.end - sl.start;

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

    std::lock_guard<std::mutex> lock(fc->mutex);

    auto ev =
	std::make_shared<event::unrecognised_datagram>(fc, sl.start, sl.end,
						       sl.time);
    mgr.handle(ev);

}

