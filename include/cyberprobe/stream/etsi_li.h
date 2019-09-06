
/****************************************************************************

ETSI LI encoding and transport.

See ETSI TS 102 232.

The code here consists of two classes:

- etsi_li, which is a transport (TCP socket) plus PDU encoding.  There is
  no state - the class just knows how to emit PDUs to a socket using supplied
  parameters.  Doesn't track sequence numbers etc.

- etsi_li_mux, which state for LIIDs, tracking sequence numbers etc.

Caller creates an etsi_li object, creates an etsi_li_mux object wrapper
around it, and invoke the methods on the etsi_li_mux.  The only things that
need to be called on the etsi_li object are connect and close.

****************************************************************************/

#ifndef CYBERPROBE_ETSI_LI_H
#define CYBERPROBE_ETSI_LI_H

#include <cyberprobe/network/socket.h>
#include <cyberprobe/stream/ber.h>
#include <cyberprobe/analyser/monitor.h>
#include <cyberprobe/stream/transport.h>
#include <cyberprobe/protocol/pdu.h>

#include <vector>
#include <string>
#include <map>
#include <queue>
#include <mutex>
#include <memory>
#include <thread>

#include <sys/time.h>

namespace cyberprobe {

    namespace etsi_li {

        using berpdu = cyberprobe::stream::ber::berpdu;
        using direction = cyberprobe::protocol::direction;
        using monitor = cyberprobe::analyser::monitor;

        // A simple ETSI LI transport implementation.
        class sender {

        private:

            // TCP socket.
            transport sock;

            // FIXME: Only currently supports 'Internet Access' profile.
            // These scenarios are defined in ETSI LI spec.

            // FIXME: Doesn't support keep-alives.

            // FIXME: Doesn't support reconnection.

            // True = the transport is connected.
            bool cnx;

        public:

            // Constructor.
            sender() {

                cnx = false;

                // 128kB buffer.
                sock.set_buffer(128 * 1024, 0);

            }

            // Destructor.
            virtual ~sender() {}

            // Returns boolean indicating whether the stream is connected.
            bool connected() { return cnx; }

            // Connect to host/port.
            void connect(const std::string& host, int port) {

                // Connect.
                sock.connect(host, port);

                cnx = true;

            }

            // Connect to host/port over TLS.
            // Also specifies the LIID for this transport.
            void connect_tls(const std::string& host, int port,
                             const std::string& keyfile, const std::string& certfile,
                             const std::string& cafile) {

                // Connect.
                sock.connect_tls(host, port, keyfile, certfile, cafile);

                cnx = true;

            }

            static void encode_psheader(berpdu& psheader_p,
                                        timeval tv,
                                        const std::string& liid,
                                        const std::string& oper,
                                        uint32_t seq, uint32_t cin,
                                        const std::string& country = "XX",
                                        const std::string& net_element = "",
                                        const std::string& int_pt = "");

            static void encode_ipiri(berpdu& ipiri_p,
                                     const std::string& username,
                                     const tcpip::address* address,
                                     int ipversion,
                                     int accessevent);

            // Close the transport.
            void close() { sock.close(); cnx = false; }

        public:

            // IA Acct start
            void ia_acct_start_request(const std::string& liid,
                                       uint32_t seq, uint32_t cin,
                                       const std::string& oper,
                                       const std::string& country = "",
                                       const std::string& net_element = "",
                                       const std::string& int_pt = "",
                                       const std::string& username = "");

            void ia_acct_start_response(const std::string& liid,
                                        const tcpip::address& target_addr,
                                        uint32_t seq, uint32_t cin,
                                        const std::string& oper,
                                        const std::string& country = "",
                                        const std::string& net_element = "",
                                        const std::string& int_pt = "",
                                        const std::string& username = "");

            void send_ip(timeval tv,
                         const std::string& liid,
                         const std::string& oper,
                         uint32_t seq, uint32_t cid,
                         const std::vector<unsigned char>& packet,
                         const std::string& country = "",
                         const std::string& net_element = "",
                         const std::string& int_pt = "",
                         direction = direction::NOT_KNOWN);

            void ia_acct_stop(const std::string& liid,
                              const std::string& oper,
                              uint32_t seq, uint32_t cin,
                              const std::string& country = "",
                              const std::string& net_element = "",
                              const std::string& int_pt = "",
                              const std::string& username = "");

        };

        // An ETSI LI mux used to wrap a transport.  This class keeps track of
        // LIIDs, CINs and sequence numbers.
        class mux {
        private:

            // The transport.
            sender& transport;

            // Map LIID to CIN and sequence numbers
            std::map<std::string, uint32_t> cin;
            std::map<std::string, uint32_t> cc_seq;
            std::map<std::string, uint32_t> iri_seq;

            // Static, the CIN which will be assigned to the next LIID.
            static uint32_t next_cin;

            // Operator and country.
            std::string oper;
            std::string country;

        public:

            // Counstructor.
            mux(sender& t) : transport(t) { }

            void target_connect(const std::string& liid,
                                const tcpip::address& target_addr,
                                const std::string& oper = "unknown",
                                const std::string& country = "",
                                const std::string& net_elt = "",
                                const std::string& int_pt = "",
                                const std::string& username = "");

            void target_disconnect(const std::string& liid,
                                   const std::string& oper = "unknown",
                                   const std::string& country = "",
                                   const std::string& net_elt = "",
                                   const std::string& int_pt = "",
                                   const std::string& username = "");

            void target_ip(timeval tv,
                           const std::string& liid,
                           const std::vector<unsigned char>& pdu,
                           const std::string& oper = "unknown",
                           const std::string& country = "",
                           const std::string& net_elt = "",
                           const std::string& int_pt = "",
                           direction dir = direction::NOT_KNOWN);

        };

        class receiver;

        // ETSI LI receiver implementation
        class connection {

        private:
            std::shared_ptr<tcpip::stream_socket> s;
            monitor& p;
            receiver &r;
            bool running;

	    std::thread* thr;

        public:
            connection(std::shared_ptr<tcpip::stream_socket> s, monitor& p,
                       receiver& r) : s(s), p(p), r(r) {
                running = true;
            }
            virtual ~connection() {}
            virtual void run();

	    // Boot thread.
	    void start() {
		thr = new std::thread(&connection::run, this);
	    }

	    virtual void join() {
		if (thr)
		    thr->join();
	    }

	    virtual void stop() {
		running = false;
	    }
        };

        // ETSI LI server.
        class receiver {

        private:
            bool running;
            monitor& p;

            std::shared_ptr<tcpip::stream_socket> svr;

            std::mutex close_me_mutex;
            std::queue<connection*> close_mes;

	    std::thread* thr;

        public:
            receiver(int port, monitor& p) : p(p) {
                running = true;
                std::shared_ptr<tcpip::stream_socket> sock(new tcpip::tcp_socket);
                svr = sock;
                svr->bind(port);
		thr = nullptr;
            }
            receiver(std::shared_ptr<tcpip::stream_socket> s, monitor& p) : p(p) {
                running = true;
                svr = s;
		thr = nullptr;
            }

            virtual ~receiver() {}
            virtual void run();
            virtual void close_me(connection* c);

	    // Boot thread.
	    void start() {
		thr = new std::thread(&receiver::run, this);
	    }

	    virtual void join() {
		if (thr)
		    thr->join();
	    }

	    virtual void stop() {
		running = false;
	    }

        };

    };

};

#endif

