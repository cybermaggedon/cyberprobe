#include <cyberprobe/protocol/gre.h>

#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/ip.h>
#include <cyberprobe/protocol/802_11.h>
#include <cyberprobe/event/event_implementations.h>

#include <arpa/inet.h>
#include <iomanip>
#include <sstream>

using namespace cyberprobe::protocol;

///////////////////////////////////////////////////////////////////////////////
// context

gre_context::gre_context(manager& mngr) : context(mngr)
{
}

gre_context::gre_context(manager& mngr,
                         const flow_address& fAddr,
                         context_ptr ctxPtr)
    : context(mngr)
{
    addr = fAddr;
    parent = ctxPtr;
}

std::string gre_context::get_type()
{
    return "gre";
}

///////////////////////////////////////////////////////////////////////////////
// gre processor

void gre::process(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice)
{
    // check there is enough room for the minimal header
    uint32_t pduLength = pduSlice.end - pduSlice.start;
    if (pduLength < sizeof(gre_header))
        {
            throw exception("PDU too small for minimal GRE header");
        }

    //parse the minimal header
    const gre_header* hdr = reinterpret_cast<const gre_header*>(&pduSlice.start[0]);

    // check the version
    // (version wrapped with other bits, mask them out)
    uint8_t version = hdr->version & 0x07;
    if (version == 0) {
        process_gre(mgr, ctx, pduSlice, hdr);
    } else if (version == 1) {
        process_pptp(mgr, ctx, pduSlice, hdr);
    } else {
        throw exception("unknown gre version " + std::to_string(version));
    }
}
std::string gre::get_next_proto(const gre_header* hdr)
{
    // work out the next protocol as string hex representation
    std::ostringstream oss;
    oss << "0x" << std::setw(2) << std::setfill('0') << std::hex << ntohs(hdr->nextProto);
    return oss.str();
}

void gre::process_gre(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const gre_header* hdr)
{
    bool checksumPresent = hdr->flags & 0x80;
    bool keyPresent = hdr->flags & 0x20;
    bool sequencePresent = hdr->flags & 0x10;

    uint32_t checksumSize = checksumPresent ? 32 : 0;
    uint32_t keySize = keyPresent ? 32 : 0;
    uint32_t sequenceSize = sequencePresent ? 32 : 0;

    uint32_t hdrSize = sizeof(gre_header) + checksumSize + keySize + sequenceSize;

    // check there is enough room now we know how big the header actually is
    uint32_t pduLength = pduSlice.end - pduSlice.start;
    if (pduLength < hdrSize)
        {
            throw exception("PDU too small for full GRE header");
        }
    pdu_iter startOfPayload = pduSlice.start + hdrSize;

    // TODO: check the checksum

    std::string nxtProto = get_next_proto(hdr);

    uint32_t key = 0;
    uint32_t sequenceNo = 0;
    if (keyPresent)
        {
            uint32_t keyIndex = sizeof(gre_header) + checksumSize;
            key = ntohl(*reinterpret_cast<const uint32_t*>(pduSlice.start[keyIndex]));
        }
    if (sequencePresent)
        {
            uint32_t seqIndex = sizeof(gre_header) + checksumSize + keySize;
            sequenceNo = ntohl(*reinterpret_cast<const uint32_t*>(pduSlice.start[seqIndex]));
        }

    // get src and dest Addresses
    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, GRE);
    dest.set(empty, TRANSPORT, GRE);

    flow_address fAddr(src, dest, pduSlice.direc);

    // get context
    gre_context::ptr flowContext = gre_context::get_or_create(ctx, fAddr);
    flowContext->set_ttl(context::default_ttl);

    uint16_t nxtProtoVal = ntohs(hdr->nextProto);

    if (nxtProtoVal == 0x8200) {
        wlan::process(mgr, flowContext, pdu_slice(startOfPayload, pduSlice.end, pduSlice.time, pduSlice.direc));
    } else if (nxtProtoVal == 0x0800 || nxtProtoVal == 0x86DD) {
        ip::process(mgr, flowContext, pdu_slice(startOfPayload, pduSlice.end, pduSlice.time, pduSlice.direc));
    } else {
        auto ev =
            std::make_shared<event::gre>(flowContext, nxtProto, key, sequenceNo,
                                         startOfPayload, pduSlice.end, pduSlice.time);
        mgr.handle(ev);
    }

}

void gre::process_pptp(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const gre_header* hdr)
{
    // check there is enough room for the minimal pptp header
    uint32_t pduLength = pduSlice.end - pduSlice.start;
    if (pduLength < sizeof(pptp_header))
        {
            throw exception("PDU too small for minimal GRE PPTP header");
        }
    //parse the minimal header
    const pptp_header* pHdr = reinterpret_cast<const pptp_header*>(&pduSlice.start[0]);

    bool sequencePresent = pHdr->flags & 0x10;
    //acknowledge flag is in the version byte
    bool ackPresent = pHdr->version & 0x80;

    uint32_t sequenceSize = sequencePresent ? 32 : 0;
    uint32_t ackSize = ackPresent ? 32 : 0;

    uint32_t hdrSize = sizeof(pptp_header) + sequenceSize + ackSize;

    // check there is enough room now we know how big the header actually is
    if (pduLength < hdrSize)
        {
            throw exception("PDU too small for full GRE PPTP header");
        }
    pdu_iter startOfPayload = pduSlice.start + hdrSize;

    std::string nxtProto = get_next_proto(hdr);

    uint32_t sequenceNo = 0;
    uint32_t ackNo = 0;
    if (sequencePresent)
        {
            sequenceNo = ntohl(*reinterpret_cast<const uint32_t*>(pduSlice.start[sizeof(pptp_header)]));
        }
    if (ackPresent)
        {
            uint32_t ackIndex =  sizeof(pptp_header) + sequenceSize;
            ackNo = ntohl(*reinterpret_cast<const uint32_t*>(pduSlice.start[ackIndex]));
        }

    // get src and dest Addresses
    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, TRANSPORT, GRE);
    dest.set(empty, TRANSPORT, GRE);

    flow_address fAddr(src, dest, pduSlice.direc);

    // get context
    gre_context::ptr flowContext = gre_context::get_or_create(ctx, fAddr);
    flowContext->set_ttl(context::default_ttl);

    uint16_t nxtProtoVal = ntohs(hdr->nextProto);
    if (nxtProtoVal == 0x8200) {
        wlan::process(mgr, flowContext, pdu_slice(startOfPayload, pduSlice.end, pduSlice.time, pduSlice.direc));
    } else if (nxtProtoVal == 0x0800 || nxtProtoVal == 0x86DD) {
        ip::process(mgr, flowContext, pdu_slice(startOfPayload, pduSlice.end, pduSlice.time, pduSlice.direc));
    } else {
        auto ev =
            std::make_shared<event::gre_pptp>(flowContext, nxtProto,
                                              ntohs(pHdr->keyPayloadLength),
                                              ntohs(pHdr->keyCallID),
                                              sequenceNo, ackNo, startOfPayload,
                                              pduSlice.end, pduSlice.time);
        mgr.handle(ev);
    }



}
