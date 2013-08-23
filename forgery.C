
#include "context.h"
#include "forgery.h"
#include "dns_protocol.h"
#include "dns.h"
#include "hexdump.h"
#include "udp.h"
#include "ip.h"

// FIXME: Why?!
#include <stdio.h>

using namespace cybermon;

void forgery::forge_dns_response(context_ptr cp, 
				 const dns_header& hdr,
				 const std::list<dns_query>& queries,
				 const std::list<dns_rr>& answers,
				 const std::list<dns_rr>& authorities,
				 const std::list<dns_rr>& additional)
{

    if (cp->get_type() != "dns")
	throw exception("Not a DNS context");

    context_ptr tmp = cp->parent.lock();
    if (tmp->get_type() != "udp")
	throw exception("Only know how to forge DNS over UDP");

    udp_context::ptr uc = 
	boost::dynamic_pointer_cast<udp_context>(tmp);

    tmp = uc->parent.lock();
    if (tmp->get_type() != "ip4")
	throw exception("Only know how to forge DNS over IPv4");

    ip4_context::ptr ic = 
	boost::dynamic_pointer_cast<ip4_context>(tmp);

    std::string src_address = ic->addr.src.to_ip_string();
    std::string dest_address = ic->addr.dest.to_ip_string();
    unsigned short src_port = uc->addr.src.get_16b();
    unsigned short dest_port = uc->addr.dest.get_16b();

    pdu fake_response;
    std::back_insert_iterator<pdu> bk = back_inserter(fake_response);

    encode_dns_header(bk, hdr);
    encode_dns_queries(bk, queries);
    encode_dns_rr(bk, answers);
    encode_dns_rr(bk, authorities);
    encode_dns_rr(bk, additional);

#ifdef DONT_WORK
    // Send forged DNS message.
    tcpip::udp_socket sock;
    sock.connect(src_address, port);
    sock.write(fake_response);
    sock.close();
#endif

    pdu ip_packet;
    encode_ip_udp_header(ip_packet, 
			 ic->addr.dest, dest_port,
			 ic->addr.src, src_port,
			 fake_response);

    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
	perror("socket");
	exit(1);
    }

    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    std::copy(ic->addr.dest.addr.begin(),
	      ic->addr.dest.addr.end(),
	      (unsigned char*) &(sin.sin_addr.s_addr));
    sin.sin_port = 0;
    
    int ret = connect(sock, (struct sockaddr*) &sin, sizeof(sin));
    if (ret < 0) {
	perror("connect");
	exit(1);
    }

    int yes = 1;
    ret = setsockopt(sock, 0, IP_HDRINCL, (char *) &yes, sizeof(yes));
    if (ret < 0) {
	perror("setsockopt");
	exit(1);
    }

    std::string interface = "lo";
    ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(),
		     interface.size());
    if (ret < 0) {
	perror("setsockopt");
	exit(1);
    }

    char tmpbuf[ip_packet.size()];
    std::copy(ip_packet.begin(), ip_packet.end(), tmpbuf);

    ret = send(sock, tmpbuf, ip_packet.size(), 0);
    if (ret < 0) {
	perror("send");
	exit(1);
    }

}

void forgery::encode_dns_header(std::back_insert_iterator<pdu> bk,
				const dns_header& hdr)
{
    
    *bk = (hdr.id & 0xff00) >> 8;
    *bk = hdr.id & 0xff;

    uint8_t flags;
    flags = 
	(hdr.qr << 7) +
	(hdr.opcode << 3) + 
	(hdr.aa << 2) + 
	(hdr.tc << 1) +
	(hdr.rd);

    *bk = flags;

    flags = (hdr.ra << 7) + (hdr.rcode);
    *bk = flags;

    *bk = (hdr.qdcount & 0xff00) >> 8;
    *bk = hdr.qdcount & 0xff;

    *bk = (hdr.ancount & 0xff00) >> 8;
    *bk = hdr.ancount & 0xff;

    *bk = (hdr.nscount & 0xff00) >> 8;
    *bk = hdr.nscount & 0xff;

    *bk = (hdr.arcount & 0xff00) >> 8;
    *bk = hdr.arcount & 0xff;

}

void forgery::encode_dns_queries(std::back_insert_iterator<pdu> bk,
				 const std::list<dns_query>& queries)
{
    
    for(std::list<dns_query>::const_iterator it = queries.begin();
	it != queries.end();
	it++) {

	encode_dns_name(bk, it->name);

	*bk = (it->type & 0xff00) >> 8;
	*bk = it->type & 0xff;

	*bk = (it->cls & 0xff00) >> 8;
	*bk = it->cls & 0xff;

    }

}

void forgery::encode_dns_name(std::back_insert_iterator<pdu> bk,
			      const std::string& n)
{

    std::string name = n;

    while (name != "") {
	
	std::string tok;
	if (name.find(".") != -1) {
	    tok = name.substr(0, name.find("."));
	    name = name.substr(name.find(".") + 1);
	} else {
	    tok = name;
	    name = "";
	}
	
	if (tok != "") {
	    *bk = tok.size();
	    std::copy(tok.begin(), tok.end(), bk);
	}
	
    }
    
    *bk = 0;

}

void forgery::encode_dns_rr(std::back_insert_iterator<pdu> bk,
			    const std::list<dns_rr>& rrs)
{

    for(std::list<dns_rr>::const_iterator it = rrs.begin();
	it != rrs.end();
	it++) {

	encode_dns_name(bk, it->name);

	*bk = (it->type & 0xff00) >> 8;
	*bk = it->type & 0xff;

	*bk = (it->cls & 0xff00) >> 8;
	*bk = it->cls & 0xff;

	*bk = (it->cls & 0xff000000) >> 24;
	*bk = (it->cls & 0xff0000) >> 16;
	*bk = (it->cls & 0xff00) >> 8;
	*bk = it->cls & 0xff;

	if (it->rdname != "") {
	    
	    *bk = (it->name.size() & 0xff00) >> 8;
	    *bk = it->name.size() & 0xff;

	    encode_dns_name(bk, it->rdname);

	} else if (it->rdaddress.addr.size() != 0) {

	    *bk = (it->rdaddress.addr.size() & 0xff00) >> 8;
	    *bk = it->rdaddress.addr.size() & 0xff;

	    std::copy(it->rdaddress.addr.begin(), it->rdaddress.addr.end(), 
		      bk);

	} else {
	    
	    throw exception("No RR response data to encode");

	}


    }

}

void forgery::encode_ip_udp_header(pdu& p,
				   address& src, uint16_t sport,
				   address& dest, uint16_t dport,
				   const pdu& payload)
{

    std::back_insert_iterator<pdu> bk = back_inserter(p);

    p.clear();

    // ---- IP header ------------

    // Version etc.
    *bk = 0x45;
    *bk = 0;

    // Length
    int tot_len = payload.size() + 20 + 4;
    *bk = (tot_len & 0xff00) >> 8;
    *bk = tot_len & 0xff;

    uint16_t seq = 0;

    // Seq
    *bk = (seq & 0xff00) >> 8;
    *bk = seq & 0xff;

    // Flags & frag offset
    *bk = 0;
    *bk = 0;

    // TTL
    *bk = 255;

    // Protocol = UDP
    *bk = 17;
    
    // Header checksum
    *bk = 0;
    *bk = 0;

    std::copy(src.addr.begin(), src.addr.end(), bk);
    std::copy(dest.addr.begin(), dest.addr.end(), bk);

    uint16_t cksum = ip::calculate_cksum(p.begin(), p.end());
    p[10] = (cksum & 0xff00) >> 8;
    p[11] = cksum & 0xff;

    // ---- UDP header ------------

    *bk = (sport & 0xff00) >> 8;
    *bk = sport & 0xff;

    *bk = (dport & 0xff00) >> 8;
    *bk = dport & 0xff;

    int udp_len = payload.size() + 8;
    *bk = (udp_len & 0xff00) >> 8;
    *bk = udp_len & 0xff;
    
    // Can't be bothered to checksum.
    *bk = 0;
    *bk = 0;
    
    // Append payload
    std::copy(payload.begin(), payload.end(), bk);

}

