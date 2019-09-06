
#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/protocol/tls.h>

namespace cyberprobe {

    class tls_handshake {
        using manager = cyberprobe::analyser::manager;
        using tls_context = cyberprobe::protocol::tls_context;
        using tls = cyberprobe::protocol::tls;
        using pdu_slice = cyberprobe::protocol::pdu_slice;
    public:
        static void process(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, const tls::header* hdr);
    private:
        static void clientHello(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static void serverHello(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static uint16_t commonHello(const pdu_slice& pduSlice, uint16_t length, protocol::tls_handshake_protocol::hello_base& hello);
        static void processExtensions(const pdu_slice& pduSlice, uint16_t length, std::vector<protocol::tls_handshake_protocol::extension>& exts);
        static void certificate(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static void serverKeyExchange(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static void serverHelloDone(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static void certificateRequest(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static void clientKeyExchange(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static void certificateVerify(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);
        static void finished(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, uint16_t length);

        struct common_hello {
            uint8_t majVersion;
            uint8_t minVersion;
            uint16_t date1; // split due to padding
            uint16_t date2;
            uint8_t random[28];
        };
    };


} // cybermon


#endif
