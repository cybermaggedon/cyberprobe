
#ifndef CYBERMON_TLS_H
#define CYBERMON_TLS_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/protocol/pdu.h>

namespace cyberprobe {
namespace protocol {

    class tls_context : public context {
    public:
        tls_context(manager& mgr);
        tls_context(manager& mngr,
                    const flow_address& fAddr,
                    context_ptr ctxPtr);

        virtual std::string get_type();

        typedef std::shared_ptr<tls_context> ptr;

        static context_ptr create(manager& m, const flow_address& f, context_ptr par)
            {
                context_ptr cp = context_ptr(new tls_context(m, f, par));
                return cp;
            }

        // Given a flow address, returns the child context.
        static ptr get_or_create(context_ptr base, const flow_address& f) {
            context_ptr cp = context::get_or_create(base, f, tls_context::create);
            ptr sp = std::dynamic_pointer_cast<tls_context>(cp);
            return sp;
        }

        void set_cipher_suite(uint16_t cs);
        bool get_cipher_suite(uint16_t& cs);

        // buffer for if messages are split over packets/segments
        pdu buffer;
        // the agreed cipher suite for the connection
        uint16_t cipherSuite;
        bool cipherSuiteSet;

        // flag to show if the last message was a change cipher spec message
        bool seenChangeCipherSuite;

        // flag to show if this side of the connection has finished
        bool finished;
    };

    class tls {
        using manager = cyberprobe::analyser::manager;
    public:
        static void process(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice);

        struct header {
            uint8_t contentType;
            uint8_t majorVersion;
            uint8_t minorVersion;
            // this is a bit weird, but using a uint16 gives the wrong bytes (presumably due to padding)
            // so use 2 uint8s and join them
            uint8_t length1;
            uint8_t length2;
        };
    private:
        static const header* verifyHeader(const pdu_slice& pduSlice);
        static void processMessage(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice, const header* hdr);
        static void changeCipherSpec(manager& mgr, tls_context::ptr ctx, const pdu_slice& pduSlice);
        static void survey(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const header* hdr);
        static void applicationData(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const header* hdr);
    };

}
}

#endif
