#include <cyberprobe/protocol/esp.h>

#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/event/event_implementations.h>

#include <arpa/inet.h>
#include <iomanip>
#include <sstream>

using namespace cyberprobe::protocol;

///////////////////////////////////////////////////////////////////////////////
// context

esp_context::esp_context(manager& mngr) : context(mngr)
{
}

esp_context::esp_context(manager& mngr,
                         const flow_address& fAddr,
                         context_ptr ctxPtr)
    : context(mngr)
{
    addr = fAddr;
    parent = ctxPtr;
}

std::string esp_context::get_type()
{
    return "esp";
}

///////////////////////////////////////////////////////////////////////////////
// esp processor

void esp::process(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice)
{
    // check there is enough room for the minimal header
    uint32_t pduLength = pduSlice.end - pduSlice.start;
    if (pduLength < sizeof(esp_header))
        {
            throw exception("PDU too small for ESP header");
        }

    //parse the minimal header
    const esp_header* hdr = reinterpret_cast<const esp_header*>(&pduSlice.start[0]);

    uint32_t spi = ntohl(hdr->spi);
    uint32_t seq = ntohl(hdr->sequence);
    uint32_t len = pduLength - sizeof(esp_header);

    // get src and dest Addresses
    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, ESP);
    // use spi in the destination address information, (cannot pass value have to pass
    // iterators)
    dest.set(pduSlice.start, pduSlice.start + 4, TRANSPORT, ESP);

    flow_address fAddr(src, dest, pduSlice.direc);

    // get context
    esp_context::ptr flowContext = esp_context::get_or_create(ctx, fAddr);
    flowContext->set_ttl(context::default_ttl);


    auto ev =
        std::make_shared<event::esp>(flowContext, spi, seq, len, pduSlice.start,
                                     pduSlice.end, pduSlice.time);
    mgr.handle(ev);

}
