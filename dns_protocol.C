
// Derived: http://www.ietf.org/rfc/rfc1035.txt

// Also: http://cr.yp.to/djbdns/notes.html
//     DNS packets use an ad-hoc compression method in which portions of
//     domain names can sometimes be replaced with two-byte pointers to
//     previous domain names. The precise rule is that a name can be
//     compressed if it is a response owner name, the name in NS data, the
//     name in CNAME data, the name in PTR data, the name in MX data, or one
//     of the names in SOA data. 

#include "dns_protocol.h"

using namespace cybermon;

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
    parse_header();

    parse_queries();
    parse_rrs(answers, hdr.ancount);
    parse_rrs(authorities, hdr.nscount);
    parse_rrs(additional, hdr.arcount);

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

