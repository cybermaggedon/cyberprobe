
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
    src.set(id, APPLICATION, DNS);
    dest.set(id, APPLICATION, DNS);

    flow_address f(src, dest);

    dns_context::ptr fc = dns_context::get_or_create(c, f);

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

