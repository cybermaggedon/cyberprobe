
#include <cyberprobe/protocol/tls.h>
#include <cyberprobe/protocol/unrecognised.h>
#include <cyberprobe/protocol/tls_handshake.h>
#include <cyberprobe/protocol/tls_utils.h>
#include <cyberprobe/protocol/tls_exception.h>
#include <cyberprobe/event/event_implementations.h>

#include <vector>
#include <algorithm>
#include <iomanip>
#include <arpa/inet.h>

using namespace cyberprobe::protocol;

// anonymous namespace
namespace {
    const std::vector<uint8_t> CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17, 0x18};
    const std::vector<uint8_t>::const_iterator CT_START = CONTENT_TYPES.begin();
    const std::vector<uint8_t>::const_iterator CT_END = CONTENT_TYPES.end();

} // anonymous namespace

///////////////////////////////////////////////////////////////////////////////
// context

tls_context::tls_context(manager& mngr) : context(mngr)
{
}

tls_context::tls_context(manager& mngr,
                         const flow_address& fAddr,
                         context_ptr ctxPtr)
    : context(mngr), cipherSuite(0xFFFF), cipherSuiteSet(false), seenChangeCipherSuite(false)
{
    addr = fAddr;
    parent = ctxPtr;
}

std::string tls_context::get_type()
{
    return "tls";
}

void tls_context::set_cipher_suite(uint16_t cs)
{
    cipherSuite = cs;
    cipherSuiteSet = true;
    context_ptr rev = reverse.lock();
    if (rev) {
        tls_context::ptr revPtr =
            std::dynamic_pointer_cast<tls_context>(rev);
        revPtr->cipherSuite = cs;
        revPtr->cipherSuiteSet = true;
    }
}

bool tls_context::get_cipher_suite(uint16_t& cs)
{
    if (cipherSuiteSet)
        {
            cs = cipherSuite;
            return true;
        }

    // haven't got it in this context, try the reverse.
    context_ptr rev = reverse.lock();
    if (rev) {
        tls_context::ptr revPtr =
            std::dynamic_pointer_cast<tls_context>(rev);
        if (revPtr->cipherSuiteSet)
            {
                cipherSuiteSet = true;
                cipherSuite = revPtr->cipherSuite;
                cs = cipherSuite;
                return true;
            }
    }

    // unable to get the cipherSuite
    return false;
}

///////////////////////////////////////////////////////////////////////////////
// tls processor

void tls::process(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice)
{
    // get src and dest Addresses
    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, APPLICATION, TLS);
    dest.set(empty, APPLICATION, TLS);

    flow_address fAddr(src, dest, pduSlice.direc);

    // get context
    tls_context::ptr flowContext = tls_context::get_or_create(ctx, fAddr);
    flowContext->set_ttl(context::default_ttl);

    // lock for buffer access
    std::unique_lock<std::mutex> lock(flowContext->mutex);

    // wrap all processing in a try catch, and report processing errors as unrecognised
    try
        {
            uint16_t extra = 0;
            // see if we are part way through a pdu
            if (! flowContext->buffer.empty())
                {
                    // construct new pdu of correct length
                    pdu_slice newSlice(flowContext->buffer.begin(),
                                       flowContext->buffer.end(),
                                       pduSlice.time, pduSlice.direc);
                    const header* hdr = verifyHeader(newSlice);
                    if (!hdr)
                        {
                            // TODO handle header on boundry
                            throw tls_exception("Invalid TLS Header");
                        }
                    uint16_t length = (hdr->length1 << 8) + hdr->length2;
                    extra = length + sizeof(header) - flowContext->buffer.size();
                    if (extra > (pduSlice.end - pduSlice.start)) {
                        // not enough room to fit the extra in
                        flowContext->buffer.reserve(flowContext->buffer.size() + (pduSlice.end - pduSlice.start));
                        flowContext->buffer.insert(flowContext->buffer.end(), pduSlice.start, pduSlice.end);
                        // no more data in slice to process return
                        return;
                    }
                    // we have  full message, construct the pdu and process it
                    flowContext->buffer.insert(flowContext->buffer.end(), pduSlice.start, pduSlice.start + extra);
                    pdu_slice msg(flowContext->buffer.begin(),
                                  flowContext->buffer.end(),
                                  pduSlice.time, pduSlice.direc);
                    processMessage(mgr, flowContext, msg, hdr);
                    // we're now done with the buffered PDU, and can process the rest of the slice
                    // TODO probably want a max capacity to cap this too so we dont eat loads of memory and
                    // never free it.
                    flowContext->buffer.resize(0);
                }

            // loop through the pdu processing all messages
            pdu_slice restOfSlice = pduSlice.skip(extra);
            while (restOfSlice.start < restOfSlice.end)
                {
                    const header* hdr = verifyHeader(restOfSlice);
                    if (!hdr)
                        {
                            // TODO handle header on boundry
                            throw tls_exception("Invalid TLS Header");
                        }
                    uint16_t length = (hdr->length1 << 8) + hdr->length2 + sizeof(header);
                    if (length > (restOfSlice.end - restOfSlice.start))
                        {
                            // have half a tls message, save into the buffer
                            flowContext->buffer.reserve(length);
                            flowContext->buffer.insert(flowContext->buffer.end(), restOfSlice.start, restOfSlice.end);
                            // exit the while loop, we've done as much as we can with this PDU
                            break;
                        }

                    // we have a full message to process
                    pdu_slice msg(restOfSlice.start,restOfSlice.end,
                                  restOfSlice.time, restOfSlice.direc);
                    processMessage(mgr, flowContext, msg, hdr);
                    restOfSlice = restOfSlice.skip(length);
                }
        }
    catch (tls_exception& e)
        {
            // there has been an issue with the TLS processing. Just report as unrecognised
            // (tls will still be in the context, so it can be identified)

            // find if the we're using tcp or udp and create an appropriate event
            context_ptr parent = flowContext->parent.lock();

            // Going to get locked in these next calls.
            lock.unlock();

            if (parent && parent->get_type() == "udp")
                {
                    unrecognised::process_unrecognised_datagram(mgr, flowContext, pduSlice);
                    return;
                }
            else
                {
                    unrecognised::process_unrecognised_stream(mgr, flowContext, pduSlice);
                    return;
                }
        } catch (std::exception& e) {
	throw e;
    }

}

const tls::header* tls::verifyHeader(const pdu_slice& pduSlice)
{

    // check enough bytes for the header
    unsigned long length = pduSlice.end - pduSlice.start;
    if (length < sizeof(header))
        {
            return nullptr;
        }

    // verify this looks like a TLS header
    const header* hdr = reinterpret_cast<const header*>(&pduSlice.start[0]);
    if (std::find(CT_START, CT_END, hdr->contentType) == CT_END)
        {
            return nullptr;
        }

    if (hdr->majorVersion != 3 || hdr->minorVersion > 4) {
        return nullptr;
    }

    return hdr;
}

void tls::processMessage(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, const header* hdr)
{
    // already know it is TLS header dont need to recheck
    switch (hdr->contentType) {
    case 20:
        changeCipherSpec(mgr, ctx, pduSlice);
        break;
    case 22: // handshake
        tls_handshake::process(mgr, ctx, pduSlice, hdr);
        break;
    case 23:
        applicationData(mgr, ctx, pduSlice, hdr);
        break;
    default: // catch all - just survey
        survey(mgr, ctx, pduSlice, hdr);
        break;
    }
}

void tls::changeCipherSpec(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice)
{
    pdu_slice data = pduSlice.skip(sizeof(tls::header));
    uint8_t val = *(data.start);

    ctx->seenChangeCipherSuite = true;

    auto ev =
        std::make_shared<event::tls_change_cipher_spec>(ctx, val, pduSlice.time);
    mgr.handle(ev);
}

void tls::survey(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const header* hdr)
{
    // already know it is TLS header dont need to recheck
    std::string version = tls_utils::convertTLSVersion(hdr->majorVersion, hdr->minorVersion);

    uint16_t length = (hdr->length1 << 8) + hdr->length2;

    auto ev =
        std::make_shared<event::tls_unknown>(ctx, version, hdr->contentType,
                                             length, pduSlice.time);
    mgr.handle(ev);
}

void tls::applicationData(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const header* hdr)
{
    // already know it is TLS header dont need to recheck
    std::string version = tls_utils::convertTLSVersion(hdr->majorVersion, hdr->minorVersion);

    uint16_t length = (hdr->length1 << 8) + hdr->length2;

    pdu_slice data = pduSlice.skip(sizeof(tls::header));

    if (length > (data.end - data.start ))
        {
            throw tls_exception("TLS Application Data: not enough space for data");
        }
    std::vector<uint8_t> encMessage(data.start, data.start + length);

    auto ev =
        std::make_shared<event::tls_application_data>(ctx, version, encMessage,
                                                      pduSlice.time);
    mgr.handle(ev);
}
