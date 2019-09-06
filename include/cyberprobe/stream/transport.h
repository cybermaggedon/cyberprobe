
/****************************************************************************

LI transport.

****************************************************************************/

#ifndef CYBERPROBE_TRANSPORT_H
#define CYBERPROBE_TRANSPORT_H

#include <deque>

#include <cyberprobe/network/socket.h>

#include <memory>

namespace cyberprobe {

    namespace etsi_li {

// A buffered transport.  Transmits PDUs, some PDUs are re-transmitted on
// reconnect.
        class transport {

        private:

            // TCP socket.
            tcpip::stream_socket* conn;

            // True = the transport is connected.
            bool cnx;

            unsigned long cap_bytes;
            unsigned long cap_pdus;

            unsigned long cur_bytes;
            unsigned long cur_pdus;

            typedef std::vector<unsigned char> pdu;
            typedef std::shared_ptr<pdu> pdu_ptr;

            std::deque<pdu_ptr> buffer;

        public:

            // Constructor.
            transport() { cnx = false; conn = 0; }

            // Destructor.
            virtual ~transport() {
                if (conn) {
                    conn->close();
                    delete conn;
                }
            }

            // Returns boolean indicating whether the stream is connected.
            bool connected() { return cnx; }

            // Connect to host/port.  Also specifies the LIID for this transport.
            void connect(const std::string& host, int port) {

                // All exceptions left thrown.

                if (conn) {
                    conn->close();
                    delete conn;
                    conn = 0;
                }

                cnx = false;

                tcpip::tcp_socket* sock = new tcpip::tcp_socket();
                conn = sock;

                sock->connect(host, port);
                cnx = true;

                // Turn off socket linger, so that close-down is quick.
                sock->set_linger(false, 0);

                for(std::deque<pdu_ptr>::iterator it = buffer.begin();
                    it != buffer.end();
                    it++) {
	    
                    conn->write(**it);

                }

            }

            // Connect to host/port.  Also specifies the LIID for this transport.
            void connect_tls(const std::string& host, int port, const std::string& key,
                             const std::string& cert, const std::string& ca) {

                // All exceptions left thrown.

                if (conn) {
                    conn->close();
                    delete conn;
                    conn = 0;
                }

                cnx = false;

                tcpip::ssl_socket* sock = new tcpip::ssl_socket();
                conn = sock;
	
                sock->use_key_file(key);
                sock->use_certificate_file(cert);
                sock->use_certificate_chain_file(ca);
                sock->check_private_key();

                sock->connect(host, port);
	
                cnx = true;

                // Set socket linger off, so that close-down is quick.
                sock->set_linger(false, 0);

                for(std::deque<pdu_ptr>::iterator it = buffer.begin();
                    it != buffer.end();
                    it++) {
	    
                    conn->write(**it);

                }

            }

            // Close the transport.
            void close() {
                if (conn) {
                    conn->close();
                    delete conn;
                    conn = 0;
                }
                cnx = false;
            }

            // Send a PDU.
            int write(pdu_ptr pdu) {

                buffer.push_back(pdu);
                cur_pdus++;
                cur_bytes += pdu->size();
	
                // If removing the front PDU would still leave plenty of stuff in
                // the buffer...
                while (!buffer.empty() && 
                       ((cur_bytes - buffer.front()->size()) > cap_bytes) &&
                       ((cur_pdus - 1) > cap_pdus)) {

                    // ...then delete that item.

                    cur_pdus--;
                    cur_bytes -= buffer.front()->size();
                    buffer.pop_front();
	    
                }

                // May except.
                int ret = conn->write(*pdu);

                if (ret < 0)
                    throw std::runtime_error("Didn't transmit PDU");
	
                if ((unsigned int)ret != pdu->size())
                    throw std::runtime_error("Didn't transmit PDU");

                return ret;
	
            }

            // Configure buffering.
            void set_buffer(unsigned long bytes, unsigned long pdus) {
                cap_bytes = bytes;
                cap_pdus = pdus;
            }

        };

    };

};

#endif

