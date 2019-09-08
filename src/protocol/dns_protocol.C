
// Derived: http://www.ietf.org/rfc/rfc1035.txt
//
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// Also: http://cr.yp.to/djbdns/notes.html
//     DNS packets use an ad-hoc compression method in which portions of
//     domain names can sometimes be replaced with two-byte pointers to
//     previous domain names. The precise rule is that a name can be
//     compressed if it is a response owner name, the name in NS data, the
//     name in CNAME data, the name in PTR data, the name in MX data, or one
//     of the names in SOA data. 

#include <cyberprobe/protocol/dns_protocol.h>

using namespace cyberprobe::protocol;

pdu_iter& dns_decoder::validate_iter(pdu_iter& pos, pdu_iter e)
{
    if (pos >= e)
        {
            throw std::runtime_error("Invalid DNS body");
        }
    return pos;
}

void dns_decoder::parse_name(pdu_iter ms, pdu_iter me, 
			     pdu_iter& pos, pdu_iter e, std::string& name,
			     bool& first)
{

    // Save this for later.
    pdu_iter start = pos;

    validate_iter(pos, e);

    while (1) {
	uint8_t len = *(validate_iter(pos, e)++);

	if (len == 0) break;

	if ((len & 0xc0) == 0xc0) {
	    const uint16_t offset = ((len & 0x3f)<<8) +
		*(validate_iter(pos, e)++);

	    if (offset > (me - ms))
		throw std::runtime_error("Invalid DNS offset");

	    pdu_iter pos2 = ms + offset;

	    // No point calling myself with the same args, that would be
	    // infinite loop.
	    if (pos2 == start)
		throw std::runtime_error("Infinite loop in DNS structure.");

	    parse_name(ms, me, pos2, me, name, first);
	    return;

	}

	if (first)
	    first = false;
	else
	    name += ".";

	for(int i = 0; i < len; i++) {
	    name += *(validate_iter(pos, e)++);
	}
    }
	
}

void dns_decoder::parse()
{

    queries.clear();

    parse_header(s);

    // DNS header length.
    ptr = s + 12;

    parse_queries();
    parse_rrs(answers, hdr.ancount);
    parse_rrs(authorities, hdr.nscount);
    parse_rrs(additional, hdr.arcount);

}

void dns_decoder::parse_header(pdu_iter header)
{
    hdr.id = (header[0] << 8) + header[1];
    hdr.qr = (header[2] & 0x80) >> 7;
    hdr.opcode = (header[2] & 0x70) >> 4;
    hdr.aa = (header[2] & 8) >> 3;
    hdr.tc = (header[2] & 4) >> 2;
    hdr.rd = (header[2] & 2) >> 1;
    hdr.ra = (header[2] & 1);
    hdr.rcode = (header[3] & 0xf);
    
    hdr.qdcount = (header[4] << 8) + header[5];
    hdr.ancount = (header[6] << 8) + header[7];
    hdr.nscount = (header[8] << 8) + header[9];
    hdr.arcount = (header[10] << 8) + header[11];

}

void dns_decoder::parse_queries() {

    dns_query q;

    for(int i = 0; i < hdr.qdcount; i++) {

	q.name = "";
	bool first = true;
	parse_name(s, e, ptr, e, q.name, first);

	q.type = ((*(validate_iter(ptr, e)++)) << 8) + *(validate_iter(ptr, e)++);
	q.cls = ((*(validate_iter(ptr, e)++)) << 8) + *(validate_iter(ptr, e)++);
	
	queries.push_back(q);

    }
    
}

void dns_decoder::parse_rr(dns_rr& rr)
{

    rr.name = "";
    bool first = true;
    parse_name(s, e, ptr, e, rr.name, first);
    
    rr.type = ((*(validate_iter(ptr, e)++)) << 8) + *(validate_iter(ptr, e)++);
    rr.cls = ((*(validate_iter(ptr, e)++)) << 8) + *(validate_iter(ptr, e)++);
    rr.ttl = ((*(validate_iter(ptr, e)++)) << 24) + ((*(validate_iter(ptr, e)++)) << 16) + 
	((*(validate_iter(ptr, e)++)) << 8) + (*(validate_iter(ptr, e)++));
    int rdlength = ((*(validate_iter(ptr, e)++)) << 8) + *(validate_iter(ptr, e)++);
    
    rr.rdata.clear();
    for(int cnt2 = 0;  cnt2 < rdlength; cnt2++)
	rr.rdata.push_back(*(validate_iter(ptr, e)++));

    if (rr.type == CNAME || rr.type == PTR || rr.type == NS ||
	rr.type == MX) {
	rr.rdname = "";
	bool first = true;
	pdu_iter ptr2 = rr.rdata.begin();
	parse_name(s, e, ptr2, rr.rdata.end(), rr.rdname, first);
    }

    if (rr.type == A) {
	if (rr.rdata.size() == 4) {
	    rr.rdaddress.set(rr.rdata, NETWORK, IP4);
	}
    }

    if (rr.type == AAAA) {
	if (rr.rdata.size() == 16) {
	    rr.rdaddress.set(rr.rdata, NETWORK, IP6);
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

