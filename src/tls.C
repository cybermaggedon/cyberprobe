#include <cybermon/tls.h>

#include <tls_handshake.h>
#include <tls_utils.h>

#include <vector>
#include <algorithm>
#include <iomanip>
#include <arpa/inet.h>

using namespace cybermon;

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
  : context(mngr)
{
  addr = fAddr;
  parent = ctxPtr;
}

std::string tls_context::get_type()
{
  return "tls";
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
  flowContext->lock.lock();

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
      throw exception("Invalid TLS Header");
    }
    uint16_t length = (hdr->length1 << 8) + hdr->length2;
    extra = length + sizeof(header) - flowContext->buffer.size();
    flowContext->buffer.resize(length + sizeof(header));
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
      throw exception("Invalid TLS Header");
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

  // release lock now we aren't going to update
  flowContext->lock.unlock();
}

const tls::header* tls::verifyHeader(const pdu_slice& pduSlice)
{
  // check enough bytes for the header
  if ((pduSlice.end - pduSlice.start) < sizeof(header))
  {
    return nullptr;
    //throw exception("PDU too small for tls header");
  }

  // verify this looks like a TLS header
  const header* hdr = reinterpret_cast<const header*>(&pduSlice.start[0]);
  if (std::find(CT_START, CT_END, hdr->contentType) == CT_END)
  {
    return nullptr;
    //throw exception("Invalid TLS contentType: " + std::to_string(hdr->contentType));
  }

  if (hdr->majorVersion != 3 || hdr->minorVersion > 4) {
    return nullptr;
    // std::ostringstream oss;
    // oss << "Invalid TLS version: 0x";
    // oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<const uint16_t>(hdr->majorVersion);
    // oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<const uint16_t>(hdr->minorVersion);
    //
    // throw exception(oss.str());
  }

  return hdr;
}

void tls::processMessage(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, const header* hdr)
{
  // already know it is TLS header dont need to recheck

  switch (hdr->contentType) {
  case 22: // handshake
    tls_handshake::process(mgr, ctx, pduSlice, hdr);
    break;
  default: // catch all - just survey
    survey(mgr, ctx, pduSlice, hdr);
    break;
  }
}

void tls::survey(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const header* hdr)
{
  // already know it is TLS header dont need to recheck
  std::string version = tls_utils::convertTLSVersion(hdr->majorVersion, hdr->minorVersion);

  uint16_t length = (hdr->length1 << 8) + hdr->length2;

  mgr.tls(ctx, version, hdr->contentType, length, pduSlice.time);
}
