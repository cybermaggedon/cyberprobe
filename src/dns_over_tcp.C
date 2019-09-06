
#include <cyberprobe/protocol/dns_over_tcp.h>

#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/dns_context.h>
#include <cyberprobe/protocol/flow.h>
#include <cyberprobe/event/event_implementations.h>

using namespace cyberprobe::protocol;


void dns_over_tcp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

    // RFC-1035: section 4.2.2 - TCP usage
    // The message is prefixed with a two byte length field which
    // gives the message length, excluding the two byte length field.
    if ((e - s) < 2)
        {
            return;
        }

    uint16_t message_length = (s[0] << 8) + s[1];

    if (message_length < 12)
        {
            throw exception("Invalid DNS header length");
        }

    // According to the RFC there should be a 2 byte message prefix which needs
    // to be stepped over before processing the DNS message. But in situations
    // where there are reassembled segments the start pointer has been advanced
    // one byte too far. Until that is fixed this horrible hack will attempt to
    // determine if both prefix bytes are present (by comparing the value to
    // the known size of the message minus the two prefix bytes themselves) and
    // either stepping over two or one bytes as necessary.

    if (message_length == ((e - s) - 2))
        {
            // Step over the 2 byte prefix
            s+=2;
        }
    else 
        {
            // redefine the message length as the value from just the first byte.
            // This may not work in all situations but it is a hack after all!
            message_length = s[0];

            if (message_length == ((e - s) - 1))
                {
                    // Step over 1 byte of prefix
                    s+=1;
                }
        }

    // Parse DNS.
    dns_decoder dec(s, e);
    dec.parse();

    std::vector<unsigned char> id;
    id.resize(2);
    id[0] = (dec.hdr.id & 0xff00) >> 8;
    id[1] = dec.hdr.id & 0xff;
    
    address src, dest;
    src.set(id, APPLICATION, DNS);
    dest.set(id, APPLICATION, DNS);

    flow_address f(src, dest, sl.direc);

    dns_context::ptr fc = dns_context::get_or_create(c, f);

    std::lock_guard<std::mutex> lock(fc->mutex);

    auto ev =
	std::make_shared<event::dns_message>(fc, dec.hdr, dec.queries,
					     dec.answers, dec.authorities,
					     dec.additional, sl.time);
    mgr.handle(ev);

}

