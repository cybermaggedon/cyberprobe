
#include "packet_capture.h"
#include "engine.h"
#include "hexdump.h"

#include <iostream>
#include <iomanip>

class an : public pcap_reader {
private:
    analyser::engine& e;
    int count;

public:
    an(const std::string& f, analyser::engine& e) : pcap_reader(f), e(e) {
	count = 0;
    }

    virtual void handle(unsigned long len, unsigned long captured, 
			const unsigned char* f);

};

class obs : public analyser::engine {
public:
    void connection_data(const analyser::context_ptr f, analyser::pdu_iter s, 
			 analyser::pdu_iter e);
    void connection_up(const analyser::context_ptr f);
    void connection_down(const analyser::context_ptr f);
    void datagram(const analyser::context_ptr f, analyser::pdu_iter s, 
		  analyser::pdu_iter e);

    // HTTP
    virtual void http_request(const analyser::context_ptr cp,
			      const std::string& method,
			      const std::string& url,
			      const std::map<std::string,std::string>& hdr,
			      analyser::pdu_iter body_start,
			      analyser::pdu_iter body_end);
    virtual void http_response(const analyser::context_ptr cp,
			       unsigned int code,
			       const std::string& status,
			       const std::map<std::string,std::string>& hdr,
			       analyser::pdu_iter body_start,
			       analyser::pdu_iter body_end);

    virtual void trigger_up(const std::string& liid,
			    const tcpip::address& trigger_address);
    virtual void trigger_down(const std::string& liid);
};

void obs::trigger_up(const std::string& liid,
		     const tcpip::address& trigger_address)
{
    std::cerr << "Attacker " << liid << " discovered at " << trigger_address
	      << std::endl;
}

void obs::trigger_down(const std::string& liid) {
    std::cerr << "Attacker " << liid << " off the air" << std::endl;
}

void obs::connection_data(const analyser::context_ptr f, analyser::pdu_iter s, 
			  analyser::pdu_iter e)
{

    describe_src(f, std::cout);
    std::cout << " -> ";
    describe_dest(f, std::cout);
    std::cout << std::endl;

    hexdump::dump(s, e, std::cout);
    std::cout << std::endl;

}

void obs::datagram(const analyser::context_ptr f, analyser::pdu_iter s, 
		   analyser::pdu_iter e)
{

    describe_src(f, std::cout);
    std::cout << " -> ";
    describe_dest(f, std::cout);
    std::cout << std::endl;

    hexdump::dump(s, e, std::cout);
    std::cout << std::endl;

}

void obs::connection_up(const analyser::context_ptr f)
{

    describe_src(f, std::cout);
    std::cout << " -> ";
    describe_dest(f, std::cout);
    std::cout << std::endl;

    std::cerr << "  Connected." << std::endl;
    std::cout << std::endl;

}

void obs::http_request(const analyser::context_ptr f,
		       const std::string& method,
		       const std::string& url,
		       const std::map<std::string,std::string>& hdr,
		       analyser::pdu_iter body_start,
		       analyser::pdu_iter body_end)
{

    describe_src(f, std::cout);
    std::cout << " -> ";
    describe_dest(f, std::cout);
    std::cout << std::endl;

    std::cerr << "  HTTP request " << method << " " << url << std::endl;
    std::cout << std::endl;

}

void obs::http_response(const analyser::context_ptr f,
			unsigned int code,
			const std::string& status,
			const std::map<std::string,std::string>& hdr,
			analyser::pdu_iter body_start,
			analyser::pdu_iter body_end)
{

    describe_src(f, std::cout);
    std::cout << " -> ";
    describe_dest(f, std::cout);
    std::cout << std::endl;

    std::cerr << "  HTTP response " << code << " " << status << std::endl;
    std::cout << std::endl;

}

void obs::connection_down(const analyser::context_ptr f)
{

    describe_src(f, std::cout);
    std::cout << " -> ";
    describe_dest(f, std::cout);
    std::cout << std::endl;

    std::cerr << "  Disconnected." << std::endl;
    std::cout << std::endl;

}

void an::handle(unsigned long len, unsigned long captured, 
		const unsigned char* f)
{

    int datalink = pcap_datalink(p);

    if (datalink == DLT_EN10MB) {

	// IPv4 ethernet only
	if (f[12] != 8) return;
	if (f[13] != 0) return;

	std::vector<unsigned char> v;
	v.assign(f + 14, f + len);

	// FIXME: Hard-coded?!
	std::string liid = "123456";

//	try {
	    e.process(liid, v.begin(), v.end());
//	} catch (std::exception& e) {
//	    std::cerr << "Packet not processed: " << e.what() << std::endl;
//	}
    }

}


int main(int argc, char** argv)
{

    obs y;

    an a("-", y);

    a.run();

}

