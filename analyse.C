
#include "packet_capture.h"
#include "analyser.h"
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
    void data(const analyser::context_ptr f, analyser::pdu_iter s, 
	      analyser::pdu_iter e);
};

void obs::data(const analyser::context_ptr f, analyser::pdu_iter s, 
	       analyser::pdu_iter e)
{

    describe(f, std::cout);
    std::cout << std::endl;

    hexdump::dump(s, e, std::cout);
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
	analyser::context_ptr c = e.get_root_context("123456");

//	try {
	    e.process(c, v.begin(), v.end());
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

