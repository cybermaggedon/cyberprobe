
#include <cyberprobe/protocol/802_11.h>
#include <cyberprobe/event/event_implementations.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/util/hardware_addr_utils.h>

using namespace cyberprobe::protocol;

///////////////////////////////////////////////////////////////////////////////
// context

wlan_context::wlan_context(manager& mngr) : context(mngr)
{
}

wlan_context::wlan_context(manager& mngr,
                           const flow_address& fAddr,
                           context_ptr ctxPtr)
    : context(mngr)
{
    addr = fAddr;
    parent = ctxPtr;
}

std::string wlan_context::get_type()
{
    return "802.11";
}

///////////////////////////////////////////////////////////////////////////////
// wlan processor - mostly survey only, not all cases are covered

void wlan::process(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice)
{
    // check there is enough room for the minimal header
    uint32_t pduLength = pduSlice.end - pduSlice.start;
    if (pduLength < sizeof(wlan_header))
        {
            throw exception("PDU too small for minimal 802.11 header");
        }

    //parse the minimal header
    const wlan_header* hdr = reinterpret_cast<const wlan_header*>(&pduSlice.start[0]);

    uint8_t version = (ntohs(hdr->frame_controls) & 0x0300) >> 8;
    uint8_t type = (ntohs(hdr->frame_controls) & 0x0C00) >> 10;
    uint8_t subtype = (ntohs(hdr->frame_controls) & 0xF000) >> 12;
    uint8_t flags = ntohs(hdr->frame_controls) & 0x00FF;
    bool is_protected  = flags & 0x40;
    uint8_t frag_num = hdr->seq_control & 0x000F;
    uint16_t seq_num = (hdr->seq_control & 0xFFF0) >> 4;


    // get src and dest Addresses
    std::vector<unsigned char> empty;
    address src, dest;
    src.set(pduSlice.start + 10, pduSlice.start + 16, LINK, WLAN);
    dest.set(pduSlice.start + 4, pduSlice.start + 10, LINK, WLAN);

    flow_address fAddr(src, dest, pduSlice.direc);

    // get context
    wlan_context::ptr flowContext = wlan_context::get_or_create(ctx, fAddr);
    flowContext->set_ttl(context::default_ttl);


    auto ev =
        std::make_shared<event::wlan>(flowContext, version, type, subtype,
                                      flags, is_protected, hdr->duration,
                                      util::hw_addr_utils::to_string(hdr->filt),
                                      frag_num, seq_num, pduSlice.time);
    mgr.handle(ev);

}
