
#include "dns.h"
#include "manager.h"
#include "address.h"

#include "udp.h"
#include "ip.h"

using namespace cybermon;

void dns::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    // Parse DNS.
    dns_decoder dec(s, e);
    dec.parse();

    std::vector<unsigned char> id;
    id.resize(2);
    id[0] = (dec.hdr.id & 0xff00) >> 8;
    id[1] = dec.hdr.id & 0xff;
    
    address src, dest;
    src.assign(id, APPLICATION, DNS);
    dest.assign(id, APPLICATION, DNS);

    flow f(src, dest);

    dns_context::ptr fc = dns_context::get_or_create(c, f);





    if ((dec.queries.size() == 1) &&
	(dec.hdr.qr == 0) && 
	(dec.hdr.opcode == QUERY)) {
	
	dns_query& d = dec.queries.front();
	
	if ((d.name == "bunchy.co.uk") && (d.type == A) && (d.cls == IN)) {

	    std::cerr << "Spike!" << std::endl;

	    std::cerr << "asd" << std::endl;
	    udp_context::ptr uc = 
		boost::dynamic_pointer_cast<udp_context>(c);

	    std::cerr << "asd2" << std::endl;
	    context_ptr tmp2 = uc->parent.lock();
	    std::cerr << "asd2.5" << std::endl;
	    ip4_context::ptr ic = 
		boost::dynamic_pointer_cast<ip4_context>(tmp2);

	    std::cerr << "asd3" << std::endl;
	    std::string src_address = ic->addr.src.to_ip_string();
	    unsigned short port = uc->addr.src.get_16b();
	    std::cerr << "Source address is " << src_address << std::endl;
	    std::cerr << "Source port is " << port << std::endl;


	    std::vector<unsigned char> fake_response;

	    fake_response.assign(id.begin(), id.end());

	    // Response, authoritative.
	    fake_response.push_back(0x84);

	    // Recursive response, successful response.
	    fake_response.push_back(0x80);

	    // 1 query
	    fake_response.push_back(0);
	    fake_response.push_back(1);

	    // 1 response
	    fake_response.push_back(0);
	    fake_response.push_back(1);

	    // No auth, no additional.
	    fake_response.push_back(0);
	    fake_response.push_back(0);
	    fake_response.push_back(0);
	    fake_response.push_back(0);

	    // Query section.

	    std::back_insert_iterator<pdu> bk = back_inserter(fake_response);

	    std::string tmpy;

	    tmpy = "bunchy";
	    fake_response.push_back(tmpy.size());
	    std::copy(tmpy.begin(), tmpy.end(), bk);
		
	    tmpy = "co";
	    fake_response.push_back(tmpy.size());
	    std::copy(tmpy.begin(), tmpy.end(), bk);
		
	    tmpy = "uk";
	    fake_response.push_back(tmpy.size());
	    std::copy(tmpy.begin(), tmpy.end(), bk);

	    fake_response.push_back(0);

	    fake_response.push_back(0);
	    fake_response.push_back(A);

	    fake_response.push_back(0);
	    fake_response.push_back(IN);

	    // Response section.

	    tmpy = "bunchy";
	    fake_response.push_back(tmpy.size());
	    std::copy(tmpy.begin(), tmpy.end(), bk);
		
	    tmpy = "co";
	    fake_response.push_back(tmpy.size());
	    std::copy(tmpy.begin(), tmpy.end(), bk);
		
	    tmpy = "uk";
	    fake_response.push_back(tmpy.size());
	    std::copy(tmpy.begin(), tmpy.end(), bk);

	    fake_response.push_back(0);

	    fake_response.push_back(0);
	    fake_response.push_back(A);

	    fake_response.push_back(0);
	    fake_response.push_back(IN);

	    // TTL is 255 seconds.
	    fake_response.push_back(0);
	    fake_response.push_back(0);
	    fake_response.push_back(0);
	    fake_response.push_back(255);

	    // Response length is 4.
	    fake_response.push_back(0);
	    fake_response.push_back(4);

	    // Response address is 1.2.3.4
	    fake_response.push_back(1);
	    fake_response.push_back(2);
	    fake_response.push_back(3);
	    fake_response.push_back(4);

	    // Send response.
	    tcpip::udp_socket sock;
	    sock.connect(src_address, port);
	    sock.write(fake_response);
	    sock.close();

	}

    }






    if ((e - s) < 12)
	throw exception("PDU too small to be DNS.");

    fc->lock.lock();

    try {

	mgr.dns_message(fc, dec.hdr, dec.queries, dec.answers,
			dec.authorities, dec.additional);

    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

#ifdef DEBUG
	std::cerr << "-- DNS ------" << std::endl;
	std::cerr << "Id: " << dec.hdr.id << std::endl;
	std::cerr << "QR: " << (int) dec.hdr.qr << std::endl;
	std::cerr << "Opcode: " << (int) dec.hdr.opcode << std::endl;
	std::cerr << "Rcode: " << (int) dec.hdr.rcode << std::endl;

	for(std::list<dns_query>::iterator it = dec.queries.begin();
	    it != dec.queries.end();
	    it++) {
	    std::cerr << "Query: " << it->name << " (" << it->type << ", "
		      << it->cls << ")" << std::endl;
	}

	for(std::list<dns_rr>::iterator it = dec.answers.begin();
	    it != dec.answers.end();
	    it++) {
	    std::cerr << "Answer: " << it->name << " (" << it->type << ", "
		      << it->cls << ")" << std::endl;
	    if (it->rdname != "")
		std::cerr << "  Name: " << it->rdname << std::endl;
	    if (it->addr.addr.size() != 0) {
		std::cerr << "  Address: ";
		it->addr.describe(std::cerr);
		std::cerr << std::endl;
	    }
	}

	for(std::list<dns_rr>::iterator it = dec.authorities.begin();
	    it != dec.authorities.end();
	    it++) {
	    std::cerr << "Authority: " << it->name << " (" << it->type << ", "
		      << it->cls << ")" << std::endl;
	    if (it->rdname != "")
		std::cerr << "  Name: " << it->rdname << std::endl;
	    if (it->addr.addr.size() != 0) {
		std::cerr << "  Address: ";
		it->addr.describe(std::cerr);
		std::cerr << std::endl;
	    }
	}

	for(std::list<dns_rr>::iterator it = dec.additional.begin();
	    it != dec.additional.end();
	    it++) {
	    std::cerr << "Additional: " << it->name << " (" << it->type << ", "
		      << it->cls << ")" << std::endl;
	    if (it->rdname != "")
		std::cerr << "  Name: " << it->rdname << std::endl;
	    if (it->addr.addr.size() != 0) {
		std::cerr << "  Address: ";
		it->addr.describe(std::cerr);
		std::cerr << std::endl;
	    }
	}
	std::cerr << std::endl;

#endif

}

