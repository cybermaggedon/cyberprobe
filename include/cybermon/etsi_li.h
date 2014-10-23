
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

#ifndef CYBERMON_ETSI_LI_H
#define CYBERMON_ETSI_LI_H

#include <cybermon/socket.h>
#include <cybermon/ber.h>
#include <cybermon/thread.h>
#include <cybermon/monitor.h>
#include <cybermon/transport.h>

#include <vector>
#include <string>
#include <map>
#include <queue>

namespace cybermon {

namespace etsi_li {

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

    // Connect to host/port.  Also specifies the LIID for this transport.
    void connect(const std::string& host, int port) {
	
	// Connect.
	sock.connect(host, port);

	cnx = true;

    }

    static void encode_psheader(ber::berpdu& psheader_p,
				const std::string& liid,
				const std::string& oper,
				uint32_t seq, uint32_t cin,
				const std::string& country = "XX",
				const std::string& net_element = "unknown",
				const std::string& int_pt = "unknown");

    static void encode_ipiri(ber::berpdu& ipiri_p,
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
			       const std::string& country = "XX",
			       const std::string& net_element = "unknown",
			       const std::string& int_pt = "unknown",
			       const std::string& username = "unknown");
			       
    void ia_acct_start_response(const std::string& liid,
				const tcpip::address& target_addr,
				uint32_t seq, uint32_t cin,
				const std::string& oper,
				const std::string& country = "XX",
				const std::string& net_element = "unknown",
				const std::string& int_pt = "unknown",
				const std::string& username = "unknown");

    void send_ip(const std::string& liid,
		 const std::string& oper,
		 uint32_t seq, uint32_t cid,
		 const std::vector<unsigned char>& packet,
		 const std::string& country = "XX",
		 const std::string& net_element = "unknown",
		 const std::string& int_pt = "unknown");

    void ia_acct_stop(const std::string& liid,
				const std::string& oper,
				uint32_t seq, uint32_t cin,
				const std::string& country = "XX",
				const std::string& net_element = "unknown",
				const std::string& int_pt = "unknown",
				const std::string& username = "unknown");

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
			const std::string& country = "XX",
			const std::string& net_elt = "unknown",
			const std::string& int_pt = "unknown",
			const std::string& username = "unknown");

    void target_disconnect(const std::string& liid,
			   const std::string& oper = "unknown",
			   const std::string& country = "XX",
			   const std::string& net_elt = "unknown",
			   const std::string& int_pt = "unknown",
			   const std::string& username = "unknown");

    void target_ip(const std::string& liid,
		   const std::vector<unsigned char>& pdu,
		   const std::string& oper = "unknown",
		   const std::string& country = "XX",
		   const std::string& net_elt = "unknown",
		   const std::string& int_pt = "unknown");

};

class receiver;

// ETSI LI receiver implementation
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

// ETSI LI server.
class receiver : public threads::thread {

  private:
    tcpip::tcp_socket svr;
    int port;
    bool running;
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

};

#endif

