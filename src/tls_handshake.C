#include <cyberprobe/protocol/tls_handshake.h>
#include <cyberprobe/protocol/tls_cipher_suites.h>
#include <cyberprobe/protocol/tls_utils.h>
#include <cyberprobe/protocol/tls_extensions.h>
#include <cyberprobe/protocol/tls_exception.h>
#include <cyberprobe/protocol/tls_key_exchange.h>
#include <cyberprobe/protocol/tls_handshake_protocol.h>
#include <cyberprobe/event/event_implementations.h>

#include <arpa/inet.h>
#include <iomanip>

using namespace cyberprobe;
using namespace cyberprobe::protocol;

void tls_handshake::process(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, const tls::header* hdr)
{
    // could have mutliple messages so process 1 at a time.
    uint16_t left = (hdr->length1 << 8) + hdr->length2;
    pdu_slice data = pduSlice.skip(sizeof(tls::header));

    if (ctx->seenChangeCipherSuite)
        {
            finished(mgr, ctx, data, left);
            ctx->seenChangeCipherSuite = false;
            return;
        }
    while (left > 0 && (data.end - data.start) >= 4)
        {
            const uint8_t type = data.start[0];
            const uint32_t len = ntohl(*reinterpret_cast<const uint32_t*>(&data.start[0])) & 0x00FFFFFF;

            // skip header
            data = data.skip(4);
            left -= 4;

            switch (type)
                {
                case 1:
                    clientHello(mgr, ctx, data, len);
                    break;
                case 2:
                    serverHello(mgr, ctx, data, len);
                    break;
                case 11:
                    certificate(mgr, ctx, data, len);
                    break;
                case 12:
                    serverKeyExchange(mgr, ctx, data, len);
                    break;
                case 13:
                    certificateRequest(mgr, ctx, data, len);
                    break;
                case 14:
                    serverHelloDone(mgr, ctx, data, len);
                    break;
                case 15:
                    certificateVerify(mgr, ctx, data, len);
                    break;
                case 16:
                    clientKeyExchange(mgr, ctx, data, len);
                    break;
                default:
                    auto ev =
                        std::make_shared<event::tls_handshake_generic>(ctx, type,
                                                                       len,
                                                                       pduSlice.time);
                    mgr.handle(ev);
                }

            data = data.skip(len);
            left -= len;
        }
}

uint16_t tls_handshake::commonHello(const pdu_slice& pduSlice, uint16_t length, tls_handshake_protocol::hello_base& hello)
{
    uint16_t dataLeft = length;
    pdu_iter dataPtr = pduSlice.start;
    if (dataLeft < sizeof(common_hello))
        {
            // TODO - nice handling
            throw tls_exception("not enough room for hello message");
        }

    const common_hello* ch = reinterpret_cast<const common_hello*>(&dataPtr[0]);
    dataLeft -= sizeof(common_hello);
    dataPtr += sizeof(common_hello);
    // just grab all the fields
    hello.version = tls_utils::convertTLSVersion(ch->majVersion, ch->minVersion);
    hello.randomTimestamp = (ntohs(ch->date1) << 16) + ntohs(ch->date2);
    std::copy(&ch->random[0], &ch->random[27], &hello.random[0]);
    uint16_t sessionIDLen = *dataPtr;
    dataLeft -= 1;
    dataPtr += 1;
    if (sessionIDLen > dataLeft)
        {
            // TODO - nice handling
            throw tls_exception("not enough room for hello message");
        }
    // extract the sessionID
    std::ostringstream sessionIDBuilder;
    for (int i=0; i<sessionIDLen; ++i)
        {
            sessionIDBuilder << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint16_t>(*(dataPtr + i));
        }
    hello.sessionID = sessionIDBuilder.str();

    dataLeft -= sessionIDLen;
    dataPtr += sessionIDLen;

    return length - dataLeft;
}

void tls_handshake::clientHello(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    uint16_t dataLeft = length;
    pdu_iter dataPtr = pduSlice.start;
    tls_handshake_protocol::client_hello_data data;

    uint16_t commonLength = commonHello(pduSlice, length, data);
    dataLeft -= commonLength;
    dataPtr += commonLength;

    // extract cipher suites
    uint16_t cipherSuiteLen = (dataPtr[0] << 8) + dataPtr[1];

    dataLeft -= 2;
    dataPtr += 2;

    if (cipherSuiteLen > dataLeft)
        {
            // TODO - nice handling
            throw tls_exception("not enough room for client hello message");
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
    auto ev =
	std::make_shared<event::tls_client_hello>(ctx, data, pduSlice.time);
    mgr.handle(ev);
}

void tls_handshake::serverHello(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    uint16_t dataLeft = length;
    pdu_iter dataPtr = pduSlice.start;
    tls_handshake_protocol::server_hello_data data;

    uint16_t commonLength = commonHello(pduSlice, length, data);
    dataLeft -= commonLength;
    dataPtr += commonLength;

    // extract cipher suite
    if (2 > dataLeft)
        {
            // TODO - nice handling
            throw tls_exception("not enough room for client hello message");
        }
    ctx->set_cipher_suite(ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0])));
    std::string cipherName = cipher::lookup(ctx->cipherSuite);
    data.cipherSuite = tls_handshake_protocol::cipher_suite(ctx->cipherSuite, cipherName);

    dataLeft -= 2;
    dataPtr += 2;


    // extract compression method
    if (! dataLeft)
        {
            // TODO - nice handling
            throw tls_exception("not enough room for client hello message");
        }
    uint8_t compressionId = *dataPtr;
    dataLeft -= 1;
    dataPtr += 1;
    std::string compressionName;
    if (compressionId < 224)
        {
            switch (compressionId) {
            case 0:
                compressionName = "NULL";
                break;
            case 1:
                compressionName = "DEFLATE";
                break;
            case 64:
                compressionName = "LZS";
                break;
            default:
                compressionName = "Unassigned";
                break;
            }
        } else {
        compressionName = "Reserved";
    }
    data.compressionMethod = tls_handshake_protocol::compression_method(compressionId, compressionName);

    // check for extensions and process
    if (dataLeft)
        {
            pdu_slice extSlice = pduSlice.skip(dataPtr - pduSlice.start);
            processExtensions(extSlice, dataLeft, data.extensions);
        }

    // send client hello event
    //TODO store relevent info in context
    auto ev =
	std::make_shared<event::tls_server_hello>(ctx, data, pduSlice.time);
    mgr.handle(ev);
}

void tls_handshake::processExtensions(const pdu_slice& pduSlice, uint16_t length, std::vector<tls_handshake_protocol::extension>& exts)
{
    uint16_t dataLeft = length;
    pdu_iter dataPtr = pduSlice.start;

//    uint16_t extsLen = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
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

void tls_handshake::certificate(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    uint16_t dataLeft = length;
    pdu_iter dataPtr = pduSlice.start;

    uint32_t certsLength = (dataPtr[0] << 16) + (dataPtr[1] << 8) + dataPtr[2];
    dataLeft -= 3;
    dataPtr += 3;

    std::vector<std::vector<uint8_t>> certs;
    while (certsLength > 0 && dataLeft > 0)
        {
            uint32_t certLength = (dataPtr[0] << 16) + (dataPtr[1] << 8) + dataPtr[2];
            dataLeft -= 3;
            dataPtr += 3;
            certsLength -= 3;

            if (certLength > certsLength || certLength > dataLeft)
                {
                    // TODO - nice handling
                    throw tls_exception("not enough room for certificate");
                }

            certs.emplace_back(dataPtr, dataPtr + certLength);

            dataLeft -= certLength;
            dataPtr += certLength;
            certsLength -= certLength;
        }

    // TODO extract cert info? - openssl?
    auto ev =
	std::make_shared<event::tls_certificates>(ctx, certs, pduSlice.time);
    mgr.handle(ev);
}


void tls_handshake::serverKeyExchange(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    uint16_t cipherSuite;
    bool success = ctx->get_cipher_suite(cipherSuite);
    if (!success)
        {
            // server key exchange without seeing the server hello... TLS Error
            throw tls_exception("TLS Protocol Error - Server Key Exchange seen before server hello.");
        }

    cipher::KeyExchangeAlgorithm algo = cipher::lookup_key_exchange_algorithm(cipherSuite);

    tls_handshake_protocol::key_exchange_data data;
    switch (algo)
        {
        case cipher::KeyExchangeAlgorithm::ec_dh:
            data.ecdh = std::make_shared<tls_handshake_protocol::ecdh_data>();
            tls_key_exchange::server_ecdh(pduSlice, length, data.ecdh);
            break;
        default:
            break;
        }

    auto ev =
	std::make_shared<event::tls_server_key_exchange>(ctx, data,
							 pduSlice.time);
    mgr.handle(ev);
}

void tls_handshake::serverHelloDone(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    auto ev =
	std::make_shared<event::tls_server_hello_done>(ctx, pduSlice.time);
    mgr.handle(ev);
}

void tls_handshake::certificateRequest(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    uint16_t dataLeft = length;
    pdu_iter dataPtr = pduSlice.start;

    tls_handshake_protocol::certificate_request_data data;

    uint8_t certTypeCount = *dataPtr;
    dataLeft -= 1;
    dataPtr += 1;

    data.certTypes.reserve(certTypeCount);
    for (int i=0; i < certTypeCount; ++i)
        {
            uint8_t certId = *dataPtr;
            dataLeft -= 1;
            dataPtr += 1;
            std::string name;
            switch (certId)
                {
                case 1:
                    name = "rsa_sign";
                    break;
                case 2:
                    name = "dss_sign";
                    break;
                case 3:
                    name = "rsa_fixed_dh";
                    break;
                case 4:
                    name = "dss_fixed_dh";
                    break;
                case 5:
                    name = "rsa_ephemeral_dh_RESERVED";
                    break;
                case 6:
                    name = "dss_ephemeral_dh_RESERVED";
                    break;
                case 20:
                    name = "fortezza_dms_RESERVED";
                    break;
                case 64:
                    name = "ecdsa_sign";
                    break;
                case 65:
                    name = "rsa_fixed_ecdh";
                    break;
                case 66:
                    name = "ecdsa_fixed_ecdh";
                    break;
                default:
                    name = "unknown - " + std::to_string(certId);
                    break;
                }
            data.certTypes.push_back(name);
        }

    uint16_t sigsLen = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
    dataLeft -= 2;
    dataPtr += 2;
    data.sigAlgos.reserve(sigsLen/2);
    for (int i=0; i < sigsLen; i+=2)
        {
            uint8_t hashAlgo = *dataPtr;
            dataLeft -= 1;
            dataPtr += 1;
            uint8_t sigAlgo = *dataPtr;
            dataLeft -= 1;
            dataPtr += 1;
            data.sigAlgos.emplace_back(hashAlgo, sigAlgo);
        }

    uint16_t distNameLen = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
    dataLeft -= 2;
    dataPtr += 2;
    data.distinguishedNames.reserve(distNameLen);
    data.distinguishedNames.insert(data.distinguishedNames.end(), dataPtr, dataPtr + distNameLen);

    auto ev =
	std::make_shared<event::tls_certificate_request>(ctx, data,
							 pduSlice.time);
    mgr.handle(ev);
}

void tls_handshake::clientKeyExchange(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    uint16_t cipherSuite;
    bool success = ctx->get_cipher_suite(cipherSuite);
    if (!success)
        {
            // client key exchange without seeing the server hello... TLS Error
            throw tls_exception("TLS Protocol Error - Client Key Exchange seen before server hello.");
        }

    cipher::KeyExchangeAlgorithm algo = cipher::lookup_key_exchange_algorithm(cipherSuite);

    std::vector<uint8_t> key;
    switch (algo)
        {
        case cipher::KeyExchangeAlgorithm::ec_dh:
            tls_key_exchange::client_ecdh(pduSlice, length, key);
            break;
        default:
            break;
        }

    auto ev =
	std::make_shared<event::tls_client_key_exchange>(ctx, key,
							 pduSlice.time);
    mgr.handle(ev);
}

void tls_handshake::certificateVerify(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    uint16_t dataLeft = length;
    pdu_iter dataPtr = pduSlice.start;

    uint8_t sigHashAlgo = dataPtr[0];
    dataPtr += 1;
    dataLeft -= 1;
    uint8_t sigAlgo = dataPtr[0];
    dataPtr += 1;
    dataLeft -= 1;

    uint16_t sigLen = ntohs(*reinterpret_cast<const uint16_t*>(&dataPtr[0]));
    dataPtr += 2;
    dataLeft -= 2;

    if (sigLen > dataLeft)
        {
            throw tls_exception("TLS Protocol Error - not enough room for signature");
        }

    std::ostringstream oss;
    for (pdu_iter iter=dataPtr;
         iter != dataPtr+sigLen;
         ++iter)
        {
            oss << std::setw(2) << std::setfill('0') << std::hex  << static_cast<const uint16_t>(*iter);
        }

    auto ev =
	std::make_shared<event::tls_certificate_verify>(ctx, sigHashAlgo,
							sigAlgo, oss.str(),
							pduSlice.time);
    mgr.handle(ev);
}

void tls_handshake::finished(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length)
{
    std::vector<uint8_t> encMessage(pduSlice.start, pduSlice.start + length);

    // create event on this finished message
    auto ev =
	std::make_shared<event::tls_handshake_finished>(ctx, encMessage,
							pduSlice.time);
    mgr.handle(ev);
    ctx->finished = true;

    // check if the entire handshake has been finished, (i.e. reverse has finished too)
    context_ptr rev = ctx->reverse.lock();
    if (rev)
        {
            tls_context::ptr revPtr = std::dynamic_pointer_cast<tls_context>(rev);
            if (revPtr->finished)
                {
                    auto ev2 =
                        std::make_shared<event::tls_handshake_complete>(ctx,
                                                                        pduSlice.time);
                    mgr.handle(ev2);
                }
        }
}
