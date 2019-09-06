
#include <cyberprobe/protocol/forgery.h>
#include <cyberprobe/util/serial.h>
#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/dns_context.h>
#include <cyberprobe/protocol/dns_protocol.h>
#include <cyberprobe/protocol/udp.h>
#include <cyberprobe/protocol/tcp.h>
#include <cyberprobe/protocol/ip.h>

using namespace cyberprobe::protocol;
using namespace cyberprobe::util;

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
	std::dynamic_pointer_cast<udp_context>(tmp);

    tmp = uc->parent.lock();
    if (tmp->get_type() != "ip4")
	throw exception("Only know how to forge DNS over IPv4");

    ip4_context::ptr ic = 
	std::dynamic_pointer_cast<ip4_context>(tmp);

    unsigned short src_port = uc->addr.src.get_uint16();
    unsigned short dest_port = uc->addr.dest.get_uint16();

    pdu fake_response;
    std::back_insert_iterator<pdu> bk = back_inserter(fake_response);

    encode_dns_header(bk, hdr);
    encode_dns_queries(bk, queries);
    encode_dns_rr(bk, answers);
    encode_dns_rr(bk, authorities);
    encode_dns_rr(bk, additional);

    pdu ip_packet;
    encode_ip_udp_header(ip_packet, 
			 ic->addr.dest, dest_port,
			 ic->addr.src, src_port,
			 fake_response);

    tcpip::raw_socket sock;
    
    sock.connect(ic->addr.src.to_ip4_string());
    sock.write(ip_packet);
    sock.close();

}

void forgery::forge_tcp_data(context_ptr cp, pdu_iter s, pdu_iter e)
{

    ip4_context::ptr ip4_ptr;
    tcp_context::ptr tcp_ptr;

    context_ptr tmp = cp;

    while (1)  {

	if (tmp->get_type() == "tcp") {
	    tcp_ptr = std::dynamic_pointer_cast<tcp_context>(tmp);
	}

	if (tmp->get_type() == "ip4") {
	    ip4_ptr = std::dynamic_pointer_cast<ip4_context>(tmp);
	}

	tmp = tmp->parent.lock();
	if (!tmp) break;
	
    }

    if (!tcp_ptr)
	throw exception("Not in a TCP context");

    if (!ip4_ptr)
	throw exception("Only know how to forge data over IPv4");

    unsigned short src_port = tcp_ptr->addr.src.get_uint16();
    unsigned short dest_port = tcp_ptr->addr.dest.get_uint16();

    uint32_t seq = tcp_ptr->seq_expected.value();
    uint32_t ack = tcp_ptr->ack_received.value();

    // Maybe should update the state?
    // tcp_ptr->ack_received += (e - s);

    pdu fake_response;
    fake_response.assign(s, e);

    pdu ip_packet;
    encode_ip_tcp_header(ip_packet, 
			 ip4_ptr->addr.dest, dest_port,
			 ip4_ptr->addr.src, src_port,
			 ack, seq, tcp::ACK,
			 fake_response);
    
    tcpip::raw_socket sock;

    sock.connect(ip4_ptr->addr.src.to_ip4_string());
    sock.write(ip_packet);
    sock.close();

}

void forgery::forge_tcp_reset(context_ptr cp)
{

    ip4_context::ptr ip4_ptr;
    tcp_context::ptr tcp_ptr;

    context_ptr tmp = cp;

    while (1)  {

	if (tmp->get_type() == "tcp") {
	    tcp_ptr = std::dynamic_pointer_cast<tcp_context>(tmp);
	}

	if (tmp->get_type() == "ip4") {
	    ip4_ptr = std::dynamic_pointer_cast<ip4_context>(tmp);
	}

	tmp = tmp->parent.lock();
	if (!tmp) break;
	
    }

    if (!tcp_ptr)
	throw exception("Not in a TCP context");

    if (!ip4_ptr)
	throw exception("Only know how to forge RST over IPv4");

    unsigned short src_port = tcp_ptr->addr.src.get_uint16();
    unsigned short dest_port = tcp_ptr->addr.dest.get_uint16();

    uint32_t seq = tcp_ptr->seq_expected.value();
    uint32_t ack = tcp_ptr->ack_received.value();

    pdu fake_response;
    pdu ip_packet;
    encode_ip_tcp_header(ip_packet, 
			 ip4_ptr->addr.dest, dest_port,
			 ip4_ptr->addr.src, src_port,
			 ack, seq, tcp::RST | tcp::ACK,
			 fake_response);

    tcpip::raw_socket sock;

    sock.connect(ip4_ptr->addr.src.to_ip4_string());
    sock.write(ip_packet);
    sock.close();

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
	int pos = name.find(".");
	if (pos != -1) {
	    tok = name.substr(0, pos);
	    name = name.substr(pos + 1);
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

    uint16_t id = 0;

    // ID
    *bk = (id & 0xff00) >> 8;
    *bk = id & 0xff;

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
    // FIXME: Checksum.
    *bk = 0;
    *bk = 0;
    
    // Append payload
    std::copy(payload.begin(), payload.end(), bk);

}


void forgery::encode_ip_tcp_header(pdu& p,
				   address& src, uint16_t sport,
				   address& dest, uint16_t dport,
				   uint32_t seq, uint32_t ack,
				   int flags,
				   const pdu& payload)
{

    std::back_insert_iterator<pdu> bk = back_inserter(p);

    p.clear();

    // ---- IP header ------------

    // Version etc.
    *bk = 0x45;
    *bk = 0;

    // Length
    int tot_len = payload.size() + 20 + 20;
    *bk = (tot_len & 0xff00) >> 8;
    *bk = tot_len & 0xff;

    uint16_t id = 8;

    // IDx
    *bk = (id & 0xff00) >> 8;
    *bk = id & 0xff;

    // Flags & frag offset
    *bk = 0;
    *bk = 0;

    // TTL
    *bk = 255;

    // Protocol = TCP
    *bk = 6;
    
    // Header checksum
    *bk = 0;
    *bk = 0;

    std::copy(src.addr.begin(), src.addr.end(), bk);
    std::copy(dest.addr.begin(), dest.addr.end(), bk);

    uint16_t cksum = ip::calculate_cksum(p.begin(), p.end());
    p[10] = (cksum & 0xff00) >> 8;
    p[11] = cksum & 0xff;

    // ---- TCP header ------------

    *bk = (sport & 0xff00) >> 8;
    *bk = sport & 0xff;

    *bk = (dport & 0xff00) >> 8;
    *bk = dport & 0xff;
    
    // Seq
    *bk = (seq & 0xff000000) >> 24;
    *bk = (seq & 0xff0000) >> 16;
    *bk = (seq & 0xff00) >> 8;
    *bk = seq & 0xff;

    *bk = (ack & 0xff000000) >> 24;
    *bk = (ack & 0xff0000) >> 16;
    *bk = (ack & 0xff00) >> 8;
    *bk = ack & 0xff;

    // Flags1
    *bk = 0x50;
    *bk = flags;

    // Window size
    *bk = 0x16;
    *bk = 0xd0;

    // Checksum
    *bk = 0;
    *bk = 0;

    // Urgent
    *bk = 0;
    *bk = 0;
    
    // Append payload
    std::copy(payload.begin(), payload.end(), bk);

    pdu_iter start = p.begin();

    // Checksum
    uint16_t sum = tcp::calculate_ip4_cksum(start + 12,  // IPv4 src
					    start + 16,  // IPv4 dest
					    6,           // TCP
					    p.size() - 20,
					    start + 20,  // Start of TCP
					    p.end());

    // Put checksum in place.
    p[36] = ((sum & 0xff00) >> 8);
    p[37] = sum & 0xff;

}

