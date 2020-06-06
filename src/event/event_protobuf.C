
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cyberprobe/event/event_implementations.h>
#include <cyberprobe/event/event_protobuf.h>
#include <cyberprobe/protocol/context.h>

#ifdef WITH_PROTOBUF
#include "cyberprobe.pb.h"
#include <google/protobuf/util/time_util.h>
#endif

#include <string.h>
#include <string>
#include <cyberprobe/network/socket.h>


// FIXME: All copied form event_json.C, should be a util class.

static std::map<int, std::string> dns_class_names = {
    {1, "IN"}, {2, "CS"}, {3, "CH"}, {4, "HS"}
};

static std::map<int, std::string> dns_type_names = {
    {1, "A"}, {2, "NS"}, {2, "NS"}, {3, "MD"}, {4, "MF"}, {5, "CNAME"}, 
    {6, "SOA"}, {7, "MB"}, {8, "MG"}, {9, "MR"}, {10, "NULL"}, {11, "WKS"}, 
    {12, "PTR"}, {13, "HINFO"}, {14, "MINFO"}, {15, "MX"}, {16, "TXT"}, 
    {17, "RP"}, {18, "AFSDB"}, {19, "X25"}, {20, "ISDN"}, {21, "RT"}, 
    {22, "NSAP"}, {23, "NSAP-PTR"}, {24, "SIG"}, {25, "KEY"}, {26, "PX"}, 
    {27, "GPOS"}, {28, "AAAA"}, {29, "LOC"}, {31, "EID"}, {32, "NIMLOC"}, 
    {33, "SRV"}, {34, "ATMA"}, {35, "NAPTR"}, {36, "KX"}, {37, "CERT"}, 
    {39, "DNAME"}, {40, "SINK"}, {41, "OPT"}, {42, "APL"}, {43, "DS"}, 
    {44, "SSHFP"}, {45, "IPSECKEY"}, {46, "RRSIG"}, {47, "NSEC"},
    {48, "DNSKEY"}, {49, "DHCID"}, {50, "NSEC3"}, {51, "NSEC3PARAM"}, 
    {52, "TLSA"}, {55, "HIP"}, {59, "CDS"}, {60, "CDNSKEY"}, {99, "SPF"}, 
    {100, "UINFO"}, {101, "UID"}, {102, "GID"}, {103, "UNSPEC"}, {249, "TKEY"}, 
    {250, "TSIG"}, {251, "IXFR"}, {252, "AXFR"}, {254, "MAILA"}, {256, "URI"}, 
    {257, "CAA"}, {32768, "TA"}, {32769, "DLV"}
};

static std::string dns_class_name(int id) {
    auto it = dns_class_names.find(id);
    if (it != dns_class_names.end())
	return it->second;
    else
	return std::to_string(id);
}

static std::string dns_type_name(int id) {
    auto it = dns_type_names.find(id);
    if (it != dns_type_names.end())
	return it->second;
    else
	return std::to_string(id);
}

namespace cyberprobe {

    namespace event {

        typedef std::pair<std::string, std::string> proto_addr;

        // FIXME: Copied from event_json.C
	static void get_addresses(context_ptr cptr,
				  std::list<proto_addr>& src,
				  std::list<proto_addr>& dest) {
	    while (cptr->get_type() != "root") {

		std::string type, address;

		cptr->get_src(type, address);
                src.push_front(proto_addr(type, address));

		cptr->get_dest(type, address);
                dest.push_front(proto_addr(type, address));

		cptr = cptr->get_parent();

	    }
	    
	}

        // Protobufify an IP address.
        static void protobufify(const std::string& addr,
                                cyberprobe::Address* a) {

            try {
                tcpip::ip4_address ip(addr);

                // Should be true.
                if (ip.addr.size() == 4) {
                    uint32_t raw =
                        ip.addr[0] << 24 |
                        ip.addr[1] << 16 |
                        ip.addr[2] << 8 |
                        ip.addr[3];
                    a->set_ipv4(raw);
                }

                // Success, it is IPv4.
                return;

            } catch (...) {
                // Failure case, fall through to IPv6.
            }

            try {
                tcpip::ip6_address ip(addr);

                // Should be true.
                if (ip.addr.size() == 16) {
                    a->set_ipv6(ip.addr.data(), ip.addr.size());
                }

                // Success, it is IPv6.
                return;

            } catch (...) {
                // Failure case, fall through to doing nothing.
            }

        }

        static void protobufify(proto_addr& addr,
                                cyberprobe::ProtocolAddress* pa) {

            cyberprobe::Protocol prot = cyberprobe::Protocol::unknown;
            cyberprobe::Protocol_Parse(addr.first, &prot);
            pa->set_protocol(prot);

            if (addr.first == "ipv4" || addr.first == "ipv6") {
                auto a = pa->mutable_address();
                protobufify(addr.second, a);
            } else if (addr.first == "udp" || addr.first == "tcp") {
                auto a = pa->mutable_address();
                a->set_port(std::stoi(addr.second));
            } else {
                // Do nothing for the address.
            }
        }

	static void protobufify_base(const protocol_event& e,
                                     cyberprobe::Event& pe,
                                     cyberprobe::Action a)
        {

	    std::list<proto_addr> src, dest;
	    get_addresses(e.context, src, dest);

            pe.set_id(e.id);
            pe.set_action(a);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.device);

            if (e.network != "")
                pe.set_network(e.network);

            using direction = cyberprobe::protocol::direction;
            
            if (e.direc == direction::FROM_TARGET)
                pe.set_origin(cyberprobe::Origin::device);
            else if (e.direc == direction::TO_TARGET)
                pe.set_origin(cyberprobe::Origin::network);

            for(auto it = src.begin();
                it != src.end();
                it++) {

                auto pa = pe.add_src();
                protobufify(*it, pa);
            }

            for(auto it = dest.begin();
                it != dest.end();
                it++) {

                auto pa = pe.add_dest();
                protobufify(*it, pa);
            }

        }
	
	void protobufify(const connection_up& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::unrecognised_stream);
            pe.mutable_connection_up();

        }
        
	void protobufify(const connection_down& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::unrecognised_stream);
            pe.mutable_connection_down();

	}

	void protobufify(const trigger_up& e, cyberprobe::Event& pe) {

            pe.set_id(e.id);
            pe.set_action(cyberprobe::Action::trigger_up);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.get_device());

            auto detail = pe.mutable_trigger_up();

            auto a = detail->mutable_address();

            protobufify(e.address, a);

	}

	void protobufify(const trigger_down& e, cyberprobe::Event& pe)
        {

            pe.set_id(e.id);
            pe.set_action(cyberprobe::Action::trigger_down);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.get_device());

            pe.mutable_trigger_down();

	}

	void protobufify(const unrecognised_stream& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::unrecognised_stream);
            
            auto detail = pe.mutable_unrecognised_stream();
            detail->set_payload(e.payload.data(), e.payload.size());
            detail->set_position(e.position);

	}

	void protobufify(const unrecognised_datagram& e,
                         cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::unrecognised_datagram);

            auto detail = pe.mutable_unrecognised_datagram();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const icmp& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::icmp_message);

            auto detail = pe.mutable_icmp();
            detail->set_type(e.type);
            detail->set_code(e.code);
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const imap& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::imap_message);

            auto detail = pe.mutable_imap();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const imap_ssl& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::imap_ssl_message);

            auto detail = pe.mutable_imap_ssl();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const pop3& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::pop3_message);

            auto detail = pe.mutable_pop3();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const pop3_ssl& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::pop3_ssl_message);

            auto detail = pe.mutable_pop3();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const rtp& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::rtp_message);

            auto detail = pe.mutable_rtp();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const rtp_ssl& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::rtp_ssl_message);

            auto detail = pe.mutable_rtp_ssl();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const sip_request& e, cyberprobe::Event& pe)
        {
            
            protobufify_base(e, pe, cyberprobe::Action::sip_request);

            auto detail = pe.mutable_sip_request();
            detail->set_method(e.method);
            detail->set_from(e.from);
            detail->set_to(e.to);
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const sip_response& e, cyberprobe::Event& pe)
        {
            
            protobufify_base(e, pe, cyberprobe::Action::sip_response);

            auto detail = pe.mutable_sip_response();
            detail->set_code(e.code);
            detail->set_status(e.status);
            detail->set_from(e.from);
            detail->set_to(e.to);
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const sip_ssl& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::sip_ssl_message);

            auto detail = pe.mutable_sip_ssl();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const smtp_auth& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::smtp_auth_message);

            auto detail = pe.mutable_smtp_auth();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const smtp_command& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::smtp_command);

            auto detail = pe.mutable_smtp_command();
            detail->set_command(e.command);

	}

	void protobufify(const smtp_response& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::smtp_response);

            auto detail = pe.mutable_smtp_response();
            detail->set_status(e.status);

            for(auto it = e.text.begin();
                it != e.text.end();
                it++)
                detail->add_text()->assign(*it);

	}

	void protobufify(const smtp_data& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::smtp_data_message);

            auto detail = pe.mutable_smtp_data();
            detail->set_from(e.from);
            detail->set_body(e.body.data(), e.body.size());

            for(auto it = e.to.begin();
                it != e.to.end();
                it++)
                detail->add_to()->assign(*it);
            
	}

	void protobufify(const http_request& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::http_request);

            pe.set_url(e.url);

            auto detail = pe.mutable_http_request();
            detail->set_method(e.method);
            detail->set_body(e.body.data(), e.body.size());

            auto hdr = detail->mutable_header();
            for(auto it = e.header.begin();
                it != e.header.end();
                it++) {
                (*hdr)[it->second.first] = it->second.second;
            }

	}

	void protobufify(const http_response& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::http_response);

            pe.set_url(e.url);

            auto detail = pe.mutable_http_response();
            detail->set_status(e.status);
            detail->set_code(e.code);
            detail->set_body(e.body.data(), e.body.size());

            auto hdr = detail->mutable_header();
            for(auto it = e.header.begin();
                it != e.header.end();
                it++) {
                (*hdr)[it->second.first] = it->second.second;
            }

	}

	void protobufify(const ftp_command& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::ftp_command);

            auto detail = pe.mutable_ftp_command();
            detail->set_command(e.command);

	}

	void protobufify(const ftp_response& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::ftp_response);

            auto detail = pe.mutable_ftp_response();
            detail->set_status(e.status);

            for(auto it = e.text.begin();
                it != e.text.end();
                it++)
                detail->add_text()->assign(*it);
     
	}

	void protobufify(const protocol::dns_header& h,
                         cyberprobe::DnsHeader* pe) {
            pe->set_id(h.id);
            pe->set_qr(h.qr);
            pe->set_opcode(h.opcode);
            pe->set_aa(h.aa);
            pe->set_tc(h.tc);
            pe->set_rd(h.rd);
            pe->set_ra(h.ra);
            pe->set_rcode(h.rcode);
            pe->set_qdcount(h.qdcount);
            pe->set_ancount(h.ancount);
            pe->set_nscount(h.nscount);
            pe->set_arcount(h.arcount);
        }

	void protobufify(const protocol::dns_query& q,
                         cyberprobe::DnsQuery* pe) {
            pe->set_name(q.name);
            pe->set_type(dns_type_name(q.type));
            pe->set_class_(dns_class_name(q.cls));
        }

	void protobufify(const protocol::dns_rr& a, cyberprobe::DnsAnswer* pe) {
            pe->set_name(a.name);
            pe->set_type(dns_type_name(a.type));
            pe->set_class_(dns_class_name(a.cls));

            if (a.rdaddress.addr.size() == 4) {
                // IPv4 address.
                std::string addr;
                addr = a.rdaddress.to_ip4_string();
                auto a = pe->mutable_address();
                protobufify(addr, a);
            }
            
            if (a.rdaddress.addr.size() == 16) {
                // IPv6 address.
                std::string addr;
                addr = a.rdaddress.to_ip6_string();
                auto a = pe->mutable_address();
                protobufify(addr, a);
            }
            
        }

	void protobufify(const dns_message& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::dns_message);

            auto detail = pe.mutable_dns_message();
            if (e.header.qr == 0)
                detail->set_type(cyberprobe::DnsMessageType::query);
            else
                detail->set_type(cyberprobe::DnsMessageType::response);

            protobufify(e.header, detail->mutable_header());

            for(auto it = e.queries.begin();
                it != e.queries.end();
                it++) {
                protobufify(*it, detail->add_query());
            }

            for(auto it = e.answers.begin();
                it != e.answers.end();
                it++) {
                protobufify(*it, detail->add_answer());
            }

            for(auto it = e.authorities.begin();
                it != e.authorities.end();
                it++) {
                protobufify(*it, detail->add_authority());
            }

            for(auto it = e.additional.begin();
                it != e.additional.end();
                it++) {
                protobufify(*it, detail->add_additional());
            }

	}

	void protobufify(const ntp_timestamp_message& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::ntp_timestamp);

            auto detail = pe.mutable_ntp_timestamp();
            detail->set_version(e.ts.m_hdr.m_version);
            detail->set_mode(e.ts.m_hdr.m_mode);

	}

	void protobufify(const ntp_control_message& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::ntp_control);

            auto detail = pe.mutable_ntp_control();
            detail->set_version(e.ctrl.m_hdr.m_version);
            detail->set_mode(e.ctrl.m_hdr.m_mode);

	}

	void protobufify(const ntp_private_message& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::ntp_private);

            auto detail = pe.mutable_ntp_private();
            detail->set_version(e.priv.m_hdr.m_version);
            detail->set_mode(e.priv.m_hdr.m_mode);

	}

	void protobufify(const gre& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::gre_message);

            auto detail = pe.mutable_gre();
            detail->set_next_proto(e.next_proto);
            detail->set_key(e.key);
            detail->set_sequence_number(e.sequence_no);
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const gre_pptp& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::gre_pptp_message);

            auto detail = pe.mutable_gre_pptp();
            detail->set_next_proto(e.next_proto);
            detail->set_call_id(e.call_id);
            detail->set_sequence_number(e.sequence_no);
            detail->set_acknowledgement_number(e.ack_no);
            detail->set_payload(e.payload.data(), e.payload.size());
            detail->set_payload_length(e.payload_length);

	}

	void protobufify(const esp& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::esp_message);

            auto detail = pe.mutable_esp();
            detail->set_sequence_number(e.sequence);
            detail->set_payload_length(e.payload_length);

	}

	void protobufify(const unrecognised_ip_protocol& e,
                         cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::unrecognised_ip_protocol);

            auto detail = pe.mutable_unrecognised_ip_protocol();
            detail->set_payload(e.payload.data(), e.payload.size());
            detail->set_next_proto(e.next_proto);
            detail->set_payload_length(e.payload_length);

	}

	void protobufify(const wlan& e, cyberprobe::Event& pe) 
        {

            protobufify_base(e, pe, cyberprobe::Action::wlan_message);

            auto detail = pe.mutable_wlan();

            detail->set_version(e.version);
            detail->set_type(e.type);
            detail->set_subtype(e.subtype);
            detail->set_flags(e.flags);
            detail->set_protected_(e.is_protected);
            detail->set_filt_addr(e.filt_addr);
            detail->set_frag_num(e.frag_num);
            detail->set_seq_num(e.seq_num);
            detail->set_duration(e.duration);

	}

	void protobufify(const tls_unknown& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::tls_unknown);

            auto detail = pe.mutable_tls_unknown();

            auto tls = detail->mutable_tls();
            tls->set_version(e.version);
            tls->set_content_type(e.content_type);
            tls->set_length(e.length);

	} 

	static std::string int_to_hex(int n) {
	    std::ostringstream buf;
	    buf << std::hex << n;
	    return buf.str();
	}

	using cipher_suite = cyberprobe::protocol::tls_handshake_protocol::
                               cipher_suite;
	void protobufify(const cipher_suite& suite, std::string* pe) {
	    if (suite.name == "Unassigned")
		*pe = suite.name + "-" + int_to_hex(suite.id);
	    *pe = suite.name;
	}

	using compression_method =
                               cyberprobe::protocol::tls_handshake_protocol::
                               compression_method;
	void protobufify(const compression_method& method, std::string* pe)
        {
	    if (method.name == "Unassigned")
		*pe = method.name + "-" + int_to_hex(method.id);
	    *pe = method.name;
	}

	using extension = cyberprobe::protocol::tls_handshake_protocol::
                               extension;
	void protobufify(const extension& ext,
                         cyberprobe::TlsClientHello_Tls_Extension* pe)
        {
            pe->set_name(ext.name);
            pe->set_length(ext.len);
            pe->set_type(ext.type);
            pe->set_data(ext.data.data(), ext.data.size());
	}

	using extension = cyberprobe::protocol::tls_handshake_protocol::
            extension;
	void protobufify(const extension& ext,
                         cyberprobe::TlsServerHello_Tls_Extension* pe)
        {
            pe->set_name(ext.name);
            pe->set_length(ext.len);
            pe->set_type(ext.type);
            pe->set_data(ext.data.data(), ext.data.size());
	}

	void protobufify(const tls_client_hello& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::tls_client_hello);

            auto detail = pe.mutable_tls_client_hello();

            auto tls = detail->mutable_tls();

            tls->set_version(e.data.version);
            tls->set_session_id(e.data.sessionID);

            auto random = tls->mutable_random();
            random->set_timestamp(e.data.randomTimestamp);
            random->set_data(e.data.random, sizeof(e.data.random));

            for(auto it = e.data.cipherSuites.begin();
                it != e.data.cipherSuites.end();
                it++) {
                protobufify(*it, tls->add_cipher_suite());
            }

            for(auto it = e.data.compressionMethods.begin();
                it != e.data.compressionMethods.end();
                it++) {
                protobufify(*it, tls->add_compression_method());
            }

            for(auto it = e.data.extensions.begin();
                it != e.data.extensions.end();
                it++) {
                protobufify(*it, tls->add_extension());
            }

	}

	void protobufify(const tls_server_hello& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::tls_server_hello);

            auto detail = pe.mutable_tls_server_hello();

            auto tls = detail->mutable_tls();

            tls->set_version(e.data.version);
            tls->set_session_id(e.data.sessionID);

            auto random = tls->mutable_random();
            random->set_timestamp(e.data.randomTimestamp);
            random->set_data(e.data.random, sizeof(e.data.random));

            auto cs = tls->mutable_cipher_suite();
            protobufify(e.data.cipherSuite, cs);

            auto cm = tls->mutable_compression_method();
            protobufify(e.data.compressionMethod, cm);

            for(auto it = e.data.extensions.begin();
                it != e.data.extensions.end();
                it++) {
                protobufify(*it, tls->add_extension());
            }

	}


	void protobufify(const tls_certificates& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::tls_certificates);

            auto detail = pe.mutable_tls_certificates();

            auto tls = detail->mutable_tls();

            for(std::vector<std::vector<uint8_t> >::const_iterator it =
		    e.certs.begin();
		it != e.certs.end();
		it++) {
                tls->add_certificate(it->data(), it->size());
	    }

	}

	using key_exchange = protocol::tls_handshake_protocol::
            key_exchange_data ;
	static void protobufify(const key_exchange& ke,
                                cyberprobe::TlsServerKeyExchange_Tls* pe)
        {
	    if (ke.ecdh) {
                pe->set_key_exchange_algorithm("ec-dh");
                auto ecdh = pe->mutable_ecdh();
                ecdh->set_curve_type(ke.ecdh->curveType);

                auto cd = ecdh->mutable_curve_metadata();
                for(auto it = ke.ecdh->curveData.begin();
                    it != ke.ecdh->curveData.end();
                    it++) {
                    (*cd)[it->name] = it->value;
                }
                ecdh->set_public_key(ke.ecdh->pubKey.data(),
                                   ke.ecdh->pubKey.size());
                ecdh->set_signature_hash_algorithm(ke.ecdh->sigHashAlgo);
                ecdh->set_signature_algorithm(ke.ecdh->sigAlgo);
                ecdh->set_signature_hash(ke.ecdh->hash);
                return;
	    }
            if (ke.dhrsa) {
                pe->set_key_exchange_algorithm("dh-rsa");
                auto dhrsa = pe->mutable_dhrsa();
                dhrsa->set_prime(ke.dhrsa->p.data(), ke.dhrsa->p.size());
                dhrsa->set_generator(ke.dhrsa->g.data(), ke.dhrsa->g.size());
                dhrsa->set_pubkey(ke.dhrsa->pubKey.data(),
                                  ke.dhrsa->pubKey.size());
                dhrsa->set_signature(ke.dhrsa->sig.data(),
                                     ke.dhrsa->sig.size());
                return;
            }
            if (ke.dhanon) {
                pe->set_key_exchange_algorithm("dh-anon");
                auto dhanon = pe->mutable_dhanon();
                dhanon->set_prime(ke.dhanon->p.data(), ke.dhanon->p.size());
                dhanon->set_generator(ke.dhanon->g.data(), ke.dhanon->g.size());
                dhanon->set_pubkey(ke.dhanon->pubKey.data(),
                                   ke.dhanon->pubKey.size());
            }
        }
            

	void protobufify(const tls_server_key_exchange& e,
                         cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_server_key_exchange);

            auto detail = pe.mutable_tls_server_key_exchange();

            auto tls = detail->mutable_tls();

            protobufify(e.data, tls);

	}

	void protobufify(const tls_server_hello_done& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_server_hello_done);

            auto detail = pe.mutable_tls_server_hello_done();

            detail->mutable_tls();

	}

	void protobufify(const tls_handshake_generic& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_handshake_generic);

            auto detail = pe.mutable_tls_handshake_generic();

            auto tls = detail->mutable_tls();

            tls->set_type(e.type);

	}

	void protobufify(const tls_certificate_request& e,
                         cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_certificate_request);

            auto detail = pe.mutable_tls_certificate_request();

            auto tls = detail->mutable_tls();

            for(auto it = e.data.certTypes.begin();
                it != e.data.certTypes.end();
                it++) {
                tls->add_certificate_type(*it);
            }

            for(auto it = e.data.sigAlgos.begin();
                it != e.data.sigAlgos.end();
                it++) {
                auto sa = tls->add_signature_algorithm();
		sa->set_hash_algorithm(it->sigHashAlgo);
		sa->set_signature_algorithm(it->sigAlgo);
            }

            tls->set_distinguished_names(e.data.distinguishedNames.data(),
                                         e.data.distinguishedNames.size());

	}

	void protobufify(const tls_client_key_exchange& e,
                         cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_client_key_exchange);

            auto detail = pe.mutable_tls_client_key_exchange();

            auto tls = detail->mutable_tls();
            tls->set_key(e.key.data(), e.key.size());

	}

	void protobufify(const tls_certificate_verify& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_certificate_verify);

            auto detail = pe.mutable_tls_certificate_verify();

            auto tls = detail->mutable_tls();

            auto sa = tls->mutable_signature_algorithm();
            sa->set_hash_algorithm(e.sig_hash_algo);
            sa->set_signature_algorithm(e.sig_algo);

            tls->set_signature(e.sig);

	}

	void protobufify(const tls_change_cipher_spec& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_change_cipher_spec);

            auto detail = pe.mutable_tls_change_cipher_spec();

            auto tls = detail->mutable_tls();
            tls->set_value(e.val);

	}

	void protobufify(const tls_handshake_finished& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_handshake_finished);

            auto detail = pe.mutable_tls_handshake_finished();

            auto tls = detail->mutable_tls();
            tls->set_message(e.msg.data(), e.msg.size());

	}

	void protobufify(const tls_handshake_complete& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_handshake_complete);

            auto detail = pe.mutable_tls_handshake_complete();

            detail->mutable_tls();

	}

	void protobufify(const tls_application_data& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe,
                             cyberprobe::Action::tls_application_data);

            auto detail = pe.mutable_tls_application_data();

            auto tls = detail->mutable_tls();
            tls->set_version(e.version);
            tls->set_length(e.data.size());

	}

    };

};

