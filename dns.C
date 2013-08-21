
// Derived: http://www.ietf.org/rfc/rfc1035.txt
// Also: http://cr.yp.to/djbdns/notes.html

//     DNS packets use an ad-hoc compression method in which portions of
//     domain names can sometimes be replaced with two-byte pointers to
//     previous domain names. The precise rule is that a name can be
//     compressed if it is a response owner name, the name in NS data, the
//     name in CNAME data, the name in PTR data, the name in MX data, or one
//     of the names in SOA data. 

#include "dns.h"
#include "manager.h"
#include "address.h"

using namespace analyser;

enum dns_rcode_t {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
    NOT_IMPLEMENTED = 4,
    REFUED = 5
};

enum dns_type_t {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    EXP_MB = 7,
    EXP_MG = 8,
    EX_MR = 9,
    EXP_NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AAAA = 28
};

enum dns_cls_t {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4
};

class dns_header {
public:

    uint16_t id;
    uint8_t qr;
    uint8_t opcode;
    uint8_t aa;
    uint8_t tc;
    uint8_t rd;
    uint8_t ra;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

class dns_query {
public:
    std::string name;
    uint16_t type;
    uint16_t cls;
};

class dns_rr {
public:
    std::string name;
    uint16_t type;
    uint16_t cls;
    uint16_t rdlength;
    pdu rdata;
    uint32_t ttl;

    std::string rdname;
    address addr;

};

class dns_decoder {
    pdu_iter s;
    pdu_iter e;
    pdu_iter ptr;

public:

    dns_header hdr;
    std::list<dns_query> queries;
    std::list<dns_rr> answers;
    std::list<dns_rr> authorities;
    std::list<dns_rr> additional;

    dns_decoder(pdu_iter s, pdu_iter e) {
	this->s = s; this->e = e;
    }
    void parse();
    void parse_header();
    void parse_name(pdu_iter ms, pdu_iter me, 
		    pdu_iter& pos, pdu_iter e, std::string&,
		    bool& first);
    void parse_queries();
    void parse_rrs(std::list<dns_rr>& rrs, int n);
    void parse_rr(dns_rr& r);
};

void dns_decoder::parse_name(pdu_iter ms, pdu_iter me, 
			     pdu_iter& pos, pdu_iter e, std::string& name,
			     bool& first)
{

    while (1) {
	uint8_t len = *(pos++);

	if (len == 0) break;

	if ((len & 0xc0) == 0xc0) {
	    uint16_t offset = (len & 0x3f) + *(pos++);
	    pdu_iter pos2 = ms + offset;

	    parse_name(ms, me, pos2, me, name, first);
	    return;

	}

	if (first)
	    first = false;
	else
	    name += ".";

	for(int i = 0; i < len; i++) {
	    name += *(pos++);
	}
    }
	
}

void dns_decoder::parse()
{

    queries.clear();

    ptr = s;
    std::cerr << "-- DNS ------" << std::endl;
    parse_header();

    std::cerr << "Id: " << hdr.id << std::endl;
    std::cerr << "QR: " << (int) hdr.qr << std::endl;
    std::cerr << "Opcode: " << (int) hdr.opcode << std::endl;
    std::cerr << "Rcode: " << (int) hdr.rcode << std::endl;

    parse_queries();
    parse_rrs(answers, hdr.ancount);
    parse_rrs(authorities, hdr.nscount);
    parse_rrs(additional, hdr.arcount);

    for(std::list<dns_query>::iterator it = queries.begin();
	it != queries.end();
	it++) {
	std::cerr << "Query: " << it->name << " (" << it->type << ", "
		  << it->cls << ")" << std::endl;
    }

    for(std::list<dns_rr>::iterator it = answers.begin();
	it != answers.end();
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

    for(std::list<dns_rr>::iterator it = authorities.begin();
	it != authorities.end();
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

    for(std::list<dns_rr>::iterator it = additional.begin();
	it != additional.end();
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

}

void dns_decoder::parse_header()
{
    hdr.id = (ptr[0] << 8) + ptr[1];
    hdr.qr = (ptr[2] & 0x80) >> 7;
    hdr.opcode = (ptr[2] & 0x70) >> 4;
    hdr.aa = (ptr[2] & 8) >> 3;
    hdr.tc = (ptr[2] & 4) >> 2;
    hdr.rd = (ptr[2] & 2) >> 1;
    hdr.ra = (ptr[2] & 1);
    hdr.rcode = (ptr[3] & 0xf);
    
    hdr.qdcount = (ptr[4] << 8) + ptr[5];
    hdr.ancount = (ptr[6] << 8) + ptr[7];
    hdr.nscount = (ptr[8] << 8) + ptr[9];
    hdr.arcount = (ptr[10] << 8) + ptr[11];

    ptr += 12;

}

void dns_decoder::parse_queries() {

    dns_query q;

    for(int i = 0; i < hdr.qdcount; i++) {

/*
	bool first = true;

	q.name = "";

	while (1) {
	    uint8_t len = *(ptr++);
	    if (len == 0) break;
	    if (first)
		first = false;
	    else
		q.name += ".";

	    for(int i = 0; i < len; i++) {
		q.name += *(ptr++);
	    }
	}
*/

	q.name = "";
	bool first = true;
	parse_name(s, e, ptr, e, q.name, first);

	q.type = ((*(ptr++)) << 8) + *(ptr++);
	q.cls = ((*(ptr++)) << 8) + *(ptr++);
	
	queries.push_back(q);

    }
    
}

void dns_decoder::parse_rr(dns_rr& rr)
{

    rr.name = "";
    bool first = true;
    parse_name(s, e, ptr, e, rr.name, first);
    
    rr.type = ((*(ptr++)) << 8) + *(ptr++);
    rr.cls = ((*(ptr++)) << 8) + *(ptr++);
    rr.ttl = ((*(ptr++)) << 24) + ((*(ptr++)) << 16) + 
	((*(ptr++)) << 8) + (*(ptr++));
    rr.rdlength = ((*(ptr++)) << 8) + *(ptr++);
    
    rr.rdata.clear();
    for(int cnt2 = 0;  cnt2 < rr.rdlength; cnt2++)
	rr.rdata.push_back(*(ptr++));

    if (rr.type == CNAME || rr.type == PTR || rr.type == NS ||
	rr.type == MX) {
	rr.rdname = "";
	bool first = true;
	pdu_iter ptr2 = rr.rdata.begin();
	parse_name(s, e, ptr2, rr.rdata.end(), rr.rdname, first);
    }

    if (rr.type == A) {
	if (rr.rdata.size() == 4) {
	    rr.addr.assign(rr.rdata, NETWORK, IP4);
	}
    }

    if (rr.type == AAAA) {
	if (rr.rdata.size() == 16) {
	    rr.addr.assign(rr.rdata, NETWORK, IP6);
	}
    }

}

void dns_decoder::parse_rrs(std::list<dns_rr>& rrs, int nr)
{

    for(int i = 0; i < nr; i++) {

	dns_rr rr;

	parse_rr(rr);
	
	rrs.push_back(rr);

    }

}

void dns::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.assign(empty, APPLICATION, DNS);
    dest.assign(empty, APPLICATION, DNS);

    flow f(src, dest);

    dns_context::ptr fc = dns_context::get_or_create(c, f);

    if ((e - s) < 12)
	throw exception("PDU too small to be DNS.");

    fc->lock.lock();

    dns_decoder dec(s, e);

    dec.parse();

#ifdef ASDASDA
    // Parse header.

    uint16_t id = (s[0] << 8) + s[1];
    uint8_t qr = (s[2] & 0x80) >> 7;
    uint8_t opcode = (s[2] & 0x70) >> 4;
    uint8_t aa = (s[2] & 8) >> 3;
    uint8_t tc = (s[2] & 4) >> 2;
    uint8_t rd = (s[2] & 2) >> 1;
    uint8_t ra = (s[2] & 1);
    uint8_t rcode = (s[3] & 0xf);
    
    uint16_t qdcount = (s[4] << 8) + s[5];
    uint16_t ancount = (s[6] << 8) + s[7];
    uint16_t nscount = (s[8] << 8) + s[9];
    uint16_t arcount = (s[10] << 8) + s[11];

    std::cerr << "-- DNS ------" << std::endl;
    std::cerr << "Id: " << id << std::endl;
    std::cerr << "QR: " << (int) qr << std::endl;
    std::cerr << "Opcode: " << (int) opcode << std::endl;
    std::cerr << "Rcode: " << (int) rcode << std::endl;

    // Parse query section.

    // Skip over header.
    pdu_iter ptr = s + 12;
    
    std::cerr << "!!!Query section!" << std::endl;

    for(int cnt = 0; cnt < qdcount; cnt++) {

	std::cerr << "Query..." << std::endl;
	while (1) {
	    uint8_t len = *(ptr++);
	    if (len == 0) break;
	    std::string label;
	    for(int i = 0; i < len; i++) {
		label += *(ptr++);
	    }
	    std::cerr << "Label: " << label << std::endl;
	}
	uint16_t qtype = ((*(ptr++)) << 8) + *(ptr++);
	uint16_t qclass = ((*(ptr++)) << 8) + *(ptr++);
	std::cerr << "Qtype: " << qtype << std::endl;
	std::cerr << "Qclass: " << qclass << std::endl;

    }

    std::cerr << "!!!!!!Answer section!" << std::endl;

    for(int cnt = 0; cnt < ancount; cnt++) {

	std::cerr << "Answer..." << std::endl;
	while (1) {
	    uint8_t len = *(ptr++);
	    if (len == 0) break;

	    if ((len & 0xc0) == 0xc0) {

		uint16_t offset = (len & 0x3f) + *(ptr++);

		pdu_iter ptr2 = s + offset;
		std::cerr <<"Compression!" << std::endl;
		std::cerr << "OFfset is " << offset << std::endl;
		while (1) {
		    uint8_t len = *(ptr2++);
		    if (len == 0) break;
		    std::string label;
		    for(int i = 0; i < len; i++) {
			label += *(ptr2++);
		    }
		    std::cerr << "Label: " << label << std::endl;
		}
		break;
	    }
	    
	    std::string label;
	    for(int i = 0; i < len; i++) {
		label += *(ptr++);
	    }
	    std::cerr << "Label: " << label << std::endl;
	}
	uint16_t type = ((*(ptr++)) << 8) + *(ptr++);
	uint16_t clss = ((*(ptr++)) << 8) + *(ptr++);
	uint32_t ttl = ((*(ptr++)) << 24) + ((*(ptr++)) << 16) + 
	    ((*(ptr++)) << 8) + (*(ptr++));
	uint16_t rdlength = ((*(ptr++)) << 8) + *(ptr++);
	std::cerr << "Type: " << type << std::endl;
	std::cerr << "Class: " << clss << std::endl;
	std::cerr << "TTL: " << ttl << std::endl;
	std::cerr << "RDLENGTH: " << rdlength << std::endl;

	for(int cnt2 = 0;  cnt2 < rdlength; cnt2++) {
	    std::cerr << std::hex << (int) *(ptr++) << " ";
	}

	// Decompress (owner, NS, CNAME, PTR, MX, SOA).

	std::cerr << std::endl;

    }

    std::cerr << "!!!!!!NS section!" << std::endl;

    for(int cnt = 0; cnt < nscount; cnt++) {

	std::cerr << "Answer..." << std::endl;
	while (1) {
	    uint8_t len = *(ptr++);
	    if (len == 0) break;

	    if ((len & 0xc0) == 0xc0) {

		uint16_t offset = (len & 0x3f) + *(ptr++);

		pdu_iter ptr2 = s + offset;
		std::cerr <<"Compression!" << std::endl;
		std::cerr << "OFfset is " << offset << std::endl;
		while (1) {
		    uint8_t len = *(ptr2++);
		    if (len == 0) break;
		    std::string label;
		    for(int i = 0; i < len; i++) {
			label += *(ptr2++);
		    }
		    std::cerr << "Label: " << label << std::endl;
		}
		break;
	    }
	    
	    std::string label;
	    for(int i = 0; i < len; i++) {
		label += *(ptr++);
	    }
	    std::cerr << "Label: " << label << std::endl;
	}
	uint16_t type = ((*(ptr++)) << 8) + *(ptr++);
	uint16_t clss = ((*(ptr++)) << 8) + *(ptr++);
	uint32_t ttl = ((*(ptr++)) << 24) + ((*(ptr++)) << 16) + 
	    ((*(ptr++)) << 8) + (*(ptr++));
	uint16_t rdlength = ((*(ptr++)) << 8) + *(ptr++);
	std::cerr << "Type: " << type << std::endl;
	std::cerr << "Class: " << clss << std::endl;
	std::cerr << "TTL: " << ttl << std::endl;
	std::cerr << "RDLENGTH: " << rdlength << std::endl;

	for(int cnt2 = 0;  cnt2 < rdlength; cnt2++) {
	    std::cerr << std::hex << (int) *(ptr++) << " ";
	}

	// Decompress (owner, NS, CNAME, PTR, MX, SOA).

	std::cerr << std::endl;

    }

    std::cerr << "!!!!!!additional section!" << std::endl;

    for(int cnt = 0; cnt < arcount; cnt++) {

	std::cerr << "Answer..." << std::endl;
	while (1) {
	    uint8_t len = *(ptr++);
	    if (len == 0) break;

	    if ((len & 0xc0) == 0xc0) {

		uint16_t offset = (len & 0x3f) + *(ptr++);

		pdu_iter ptr2 = s + offset;
		std::cerr <<"Compression!" << std::endl;
		std::cerr << "OFfset is " << offset << std::endl;
		while (1) {
		    uint8_t len = *(ptr2++);
		    if (len == 0) break;
		    std::string label;
		    for(int i = 0; i < len; i++) {
			label += *(ptr2++);
		    }
		    std::cerr << "Label: " << label << std::endl;
		}
		break;
	    }
	    
	    std::string label;
	    for(int i = 0; i < len; i++) {
		label += *(ptr++);
	    }
	    std::cerr << "Label: " << label << std::endl;
	}
	uint16_t type = ((*(ptr++)) << 8) + *(ptr++);
	uint16_t clss = ((*(ptr++)) << 8) + *(ptr++);
	uint32_t ttl = ((*(ptr++)) << 24) + ((*(ptr++)) << 16) + 
	    ((*(ptr++)) << 8) + (*(ptr++));
	uint16_t rdlength = ((*(ptr++)) << 8) + *(ptr++);
	std::cerr << "Type: " << type << std::endl;
	std::cerr << "Class: " << clss << std::endl;
	std::cerr << "TTL: " << ttl << std::endl;
	std::cerr << "RDLENGTH: " << rdlength << std::endl;

	for(int cnt2 = 0;  cnt2 < rdlength; cnt2++) {
	    std::cerr << std::hex << (int) *(ptr++) << " ";
	}

	// Decompress (owner, NS, CNAME, PTR, MX, SOA).

	std::cerr << std::endl;

    }

    std::cerr << std::endl;

#endif

    try {
//	mgr.unrecognised_stream(fc, s, e);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

