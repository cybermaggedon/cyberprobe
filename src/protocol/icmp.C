
#include <memory>

#include <cyberprobe/protocol/icmp.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/event/event_implementations.h>

using namespace cyberprobe::protocol;
using namespace cyberprobe::analyser;

void icmp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    unsigned int header_length = 8;

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

    if ((e - s) < header_length)
        {
            throw exception("Header too small for ICMP header");
        }

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, CONTROL, ICMP);
    dest.set(empty, CONTROL, ICMP);

    uint8_t type = s[0];
    uint8_t code = s[1];
    // uint16_t checksum = (s[2] << 8) + s[3];
    // uint32_t roh = (s[4] << 24) + (s[5] << 16) + (s[6] << 8) + s[7];
    // uint32_t payload_length = (e - s) - header_length;

    flow_address f(src, dest, sl.direc);

    // FIXME: Check checksum?

    icmp_context::ptr fc = icmp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    std::lock_guard<std::mutex> lock(fc->mutex);

    // Do something with the Rest Of Header (roh)?

    // Reposition pdu start pointer to the payload
    pdu_iter start_of_payload = s + header_length;

    auto ev = std::make_shared<event::icmp>(fc, type, code,
					    start_of_payload, e, sl.time);
    mgr.handle(ev);

}

