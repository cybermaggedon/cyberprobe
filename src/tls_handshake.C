#include <tls_handshake.h>
#include <tls_cipher_suites.h>
#include <tls_utils.h>
#include <tls_extensions.h>

#include <cybermon/tls_handshake_protocol.h>

#include <arpa/inet.h>
#include <iomanip>

using namespace cybermon;

void tls_handshake::process(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, const tls::header* hdr)
{
  // could have mutliple messages so process 1 at a time.
  uint16_t left = (hdr->length1 << 8) + hdr->length2;
  pdu_slice data = pduSlice.skip(sizeof(tls::header));

  while (left > 0 && (data.end - data.start) > 4)
  {
    const uint8_t type = data.start[0];
    const uint32_t len = ntohl(*reinterpret_cast<const uint32_t*>(&data.start[0])) & 0x00FFFFFF;

    // skip header
    data = data.skip(4);
    left -= 4;

    std::cout << "--------------\ntype is " << static_cast<uint16_t>(type) << " length of handshake message is " << len << std::endl;
    switch (type)
    {
    case 1:
      clientHello(mgr, ctx, data, len);
      break;
    }

    data = data.skip(len);
    left -= len;
  }
}

void tls_handshake::clientHello(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
  uint16_t dataLeft = length;
  pdu_iter dataPtr = pduSlice.start;
  if (dataLeft < sizeof(client_hello))
  {
    // TODO - nice handling
    throw exception("not enough room for client hello message");
  }

  const client_hello* ch = reinterpret_cast<const client_hello*>(&dataPtr[0]);
  dataLeft -= sizeof(client_hello);
  dataPtr += sizeof(client_hello);
  // just grab all the fields
  tls_handshake_protocol::client_hello_data data;
  data.version = tls_utils::convertTLSVersion(ch->majVersion, ch->minVersion);
  data.randomTimestamp = (ntohs(ch->date1) << 16) + ntohs(ch->date2);
  std::copy(&ch->random[0], &ch->random[27], &data.random[0]);
  uint16_t sessionIDLen = *dataPtr;
  dataLeft -= 1;
  dataPtr += 1;
  if (sessionIDLen > dataLeft)
  {
      // TODO - nice handling
      throw exception("not enough room for client hello message");
  }
  // extract the sessionID
  std::ostringstream sessionIDBuilder;
  for (int i=0; i<sessionIDLen; ++i)
  {
    sessionIDBuilder << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint16_t>(*(dataPtr + i));
  }
  data.sessionID = sessionIDBuilder.str();

  dataLeft -= sessionIDLen;
  dataPtr += sessionIDLen;

  // extract cipher suites
  uint16_t cipherSuiteLen = (dataPtr[0] << 8) + dataPtr[1];

  dataLeft -= 2;
  dataPtr += 2;

  if (cipherSuiteLen > dataLeft)
  {
      // TODO - nice handling
      throw exception("not enough room for client hello message");
  }

  data.cipherSuites.reserve(cipherSuiteLen/2);
  for (int i=0; i< cipherSuiteLen; i+=2)
  {
    const uint16_t id = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[i]));
    std::string name = cipher::lookup(id);
    data.cipherSuites.emplace_back(id, name);
  }
  dataLeft -= cipherSuiteLen;
  dataPtr += cipherSuiteLen;

  // extract compression methods
  uint8_t compressionLen = *dataPtr;
  dataLeft -= 1;
  dataPtr += 1;

  data.compressionMethods.reserve(compressionLen);
  for (int i=0; i< compressionLen; i+=2)
  {
    const uint8_t id = dataPtr[i];
    std::string name;
    if (id < 224)
    {
      switch (id) {
      case 0:
        name = "NULL";
        break;
      case 1:
        name = "DEFLATE";
        break;
      case 64:
        name = "LZS";
        break;
      default:
        name = "Unassigned";
        break;
      }
    } else {
      name = "Reserved";
    }
    data.compressionMethods.emplace_back(id, name);
  }
  dataLeft -= compressionLen;
  dataPtr += compressionLen;

  // check for extensions and process
  if (dataLeft)
  {
    pdu_slice extSlice = pduSlice.skip(dataPtr - pduSlice.start);
    processExtensions(extSlice, dataLeft, data.extensions);
  }

  // send client hello event
  //TODO store relevent info in context
  mgr.tls_client_hello(ctx, data, pduSlice.time);
}

void tls_handshake::processExtensions(const pdu_slice& pduSlice, uint16_t length, std::vector<tls_handshake_protocol::extension>& exts)
{
  uint16_t dataLeft = length;
  pdu_iter dataPtr = pduSlice.start;

  uint16_t extsLen = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
  dataLeft -= 2;
  dataPtr += 2;

  while (dataLeft > 0)
  {
    // process extension
    uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
    dataLeft -= 2;
    dataPtr += 2;
    uint16_t len = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
    dataLeft -= 2;
    dataPtr += 2;
    std::string name = tls_extensions::lookup(type);
    exts.emplace_back(type, name, len, dataPtr);

    dataLeft -= len;
    dataPtr += len;
  }

}

void tls_handshake::processMessage(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint8_t type)
{

}
