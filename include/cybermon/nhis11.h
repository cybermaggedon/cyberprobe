
#ifndef CYBERMON_NHIS11_H
#define CYBERMON_NHIS11_H

#include <cybermon/socket.h>
#include <cybermon/monitor.h>
#include <cybermon/transport.h>

#include <vector>
#include <list>
#include <queue>
#include <memory>
#include <mutex>
#include <thread>

namespace cybermon {

    namespace nhis11 {

// A simple NHIS 1.1 transport implementation.
        class sender {

        private:

            typedef std::vector<unsigned char> pdu;
            typedef std::shared_ptr<pdu> pdu_ptr;

            // TCP socket.
            etsi_li::transport s;

            // Send the START PDU.
            void send_start(const std::string& liid);

            // Send a CONTINUE PDU containing an IP packet.
            void send_ip(const std::vector<unsigned char>& pkt, 
                         unsigned long seq, unsigned long long cid,
                         bool direction);

            // Current sequence number.
            unsigned long seq;

            // The CID of this connection.
            unsigned long cid;

            // Static, the CID which will be assigned to the next NHIS 1.1 connection.
            static unsigned long next_cid;

            // True = the NHIS 1.1 transport is connected.
            bool cnx;

        public:

            // Constructor.
            sender() { cnx = false; }

            // Destructor.
            virtual ~sender() {}

            // Returns boolean indicating whether the stream is connected.
            bool connected() { return cnx; }

            // Connect to host/port.  Also specifies the LIID for this transport.
            void connect(const std::string& host, int port, const std::string& liid) {
                seq = 0;
                cid = next_cid++;
                s.connect(host, port);
                send_start(liid);
                cnx = true;
            }
    
            // Connect to host/port using TLS.  Also specifies the LIID for this
            // transport.
            void connect_tls(const std::string& host, int port, const std::string& liid,
                             const std::string& key, const std::string& cert,
                             const std::string& chain) {
                seq = 0;
                cid = next_cid++;
                s.connect_tls(host, port, key, cert, chain);
                send_start(liid);
                cnx = true;
            }

            // Deliver an IP packet.  dir describes the 'direction' as defined in
            // the NHIS 1.1 spec.
            void send(const std::vector<unsigned char>& pkt, bool dir = false) {
                send_ip(pkt, seq++, cid, dir);
            }

            // Close the transport.
            void close() { s.close(); cnx = false; }

        };

        class receiver;

// NHIS 1.1 receiver implementation
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
		thr = nullptr;
            }
            virtual ~connection() {
		delete thr;
	    }
	    
            virtual void run();

	    // Boot thread.
	    void start() {
		if (thr) {
		    delete thr;
		    thr = 0;
		}
		thr = new std::thread(&connection::run, this);
	    }

	    void join() {
		if (thr)
		    thr->join();
	    }

        };

// NHIS 1.1 server.
        class receiver {

        private:
            bool running;
            std::shared_ptr<tcpip::stream_socket> svr;
            monitor& p;

            std::mutex close_me_mutex;
            std::queue<connection*> close_mes;

	    std::thread* thr;

        public:
            receiver(int port, monitor& p) : p(p) {
                svr = std::shared_ptr<tcpip::stream_socket>(new tcpip::tcp_socket);
                svr->bind(port);
                running = true;
            }
            receiver(std::shared_ptr<tcpip::stream_socket> sock, monitor& p) : p(p) {
                svr = sock;
                running = true;
		thr = nullptr;
	
            }
            virtual ~receiver() {}
            virtual void run();
            virtual void close_me(connection* c);

	    virtual void start() {
		thr = new std::thread(&receiver::run, this);
	    }

	    virtual void stop() {
		running = false;
	    }

	    virtual void join() {
		if (thr)
		    thr->join();
	    }
    
        };

    };

};

#endif

