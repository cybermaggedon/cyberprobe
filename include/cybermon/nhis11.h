
#ifndef NHIS11_H
#define NHIS11_H

#include "socket.h"
#include "thread.h"
#include "monitor.h"
#include "transport.h"

#include <vector>
#include <list>
#include <queue>

#include <boost/shared_ptr.hpp>

namespace nhis11 {

// A simple NHIS 1.1 transport implementation.
class sender {

  private:

    typedef std::vector<unsigned char> pdu;
    typedef boost::shared_ptr<pdu> pdu_ptr;

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
class connection : public threads::thread {

  private:
    tcpip::tcp_socket s;
    monitor& p;
    receiver &r;
    bool running;

  public:
    connection(tcpip::tcp_socket s, monitor& p,
	       receiver& r) : s(s), p(p), r(r) {
	running = true;
    }
    virtual ~connection() {}
    virtual void run();
};

// NHIS 1.1 server.
class receiver : public threads::thread {

  private:
    int port;
    bool running;
    tcpip::tcp_socket svr;
    monitor& p;

    threads::mutex close_me_lock;
    std::queue<connection*> close_mes;

  public:
    receiver(int port, monitor& p) : port(port), p(p) {
	running = true;
    }
    virtual ~receiver() {}
    virtual void run();
    virtual void close_me(connection* c);
    
};

};

#endif

