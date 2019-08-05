
#include <cybermon/event_implementations.h>
#include <cybermon/event_protobuf.h>
#include <cybermon/context.h>

#include "cyberprobe.pb.h"

#include <string.h>
#include <string>

#include <google/protobuf/util/time_util.h>

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

namespace cybermon {

    namespace event {

        // FIXME: Copied from event_json.C
	static void get_addresses(context_ptr cptr,
				  std::list<std::string>& src,
				  std::list<std::string>& dest) {
	    while (cptr->get_type() != "root") {

		std::string type, address;

		cptr->get_src(type, address);
		if (address == "")
		    src.push_front(type);
		else
		    src.push_front(type + ":" + address);

		cptr->get_dest(type, address);
		if (address == "")
		    dest.push_front(type);
		else
		    dest.push_front(type + ":" + address);

		cptr = cptr->get_parent();

	    }
	    
	}

	static void protobufify_base(const protocol_event& e,
                                     cyberprobe::Event& pe,
                                     cyberprobe::Action a)
        {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

            pe.set_id(e.id);
            pe.set_action(a);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.get_device());

            for(auto it = src.begin();
                it != src.end();
                it++)
                pe.add_src()->assign(*it);

            for(auto it = dest.begin();
                it != dest.end();
                it++)
                pe.add_dest()->assign(*it);
            
        }
	
	void protobufify(const connection_up& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::unrecognised_stream);
            auto detail = pe.mutable_connection_up();

        }
        
	void protobufify(const connection_down& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::unrecognised_stream);
            auto detail = pe.mutable_connection_down();

	}

	void protobufify(const trigger_up& e, cyberprobe::Event& pe) {

            pe.set_id(e.id);
            pe.set_action(cyberprobe::Action::trigger_up);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.get_device());

            auto detail = pe.mutable_trigger_up();
            detail->set_address(e.address);

	}

	void protobufify(const trigger_down& e, cyberprobe::Event& pe)
        {

            pe.set_id(e.id);
            pe.set_action(cyberprobe::Action::trigger_down);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.get_device());

            auto detail = pe.mutable_trigger_down();

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

            protobufify_base(e, pe, cyberprobe::Action::icmp);

            auto detail = pe.mutable_icmp();
            detail->set_type(e.type);
            detail->set_code(e.code);
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const imap& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::imap);

            auto detail = pe.mutable_imap();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const imap_ssl& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::imap_ssl);

            auto detail = pe.mutable_imap_ssl();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const pop3& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::pop3);

            auto detail = pe.mutable_pop3();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const pop3_ssl& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::pop3_ssl);

            auto detail = pe.mutable_pop3();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const rtp& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::pop3_ssl);

            auto detail = pe.mutable_rtp();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const rtp_ssl& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe, cyberprobe::Action::pop3_ssl);

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

            protobufify_base(e, pe, cyberprobe::Action::sip_ssl);

            auto detail = pe.mutable_sip_ssl();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const smtp_auth& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe, cyberprobe::Action::smtp_auth);

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

            protobufify_base(e, pe, cyberprobe::Action::smtp_data);

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

            auto hdr = (*detail->mutable_header());
            for(auto it = e.header.begin();
                it != e.header.end();
                it++) {
                
                hdr[it->second.first] = it->second.second;
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

            auto hdr = (*detail->mutable_header());
            for(auto it = e.header.begin();
                it != e.header.end();
                it++) {
                
                hdr[it->second.first] = it->second.second;
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

	void protobufify(const dns_header& h, cyberprobe::DnsHeader* pe) {
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

	void protobufify(const dns_query& q, cyberprobe::DnsQuery* pe) {
            pe->set_name(q.name);
            pe->set_type(dns_type_name(q.type));
            pe->set_class_(dns_class_name(q.cls));
        }

	void protobufify(const dns_rr& a, cyberprobe::DnsAnswer* pe) {
            pe->set_name(a.name);
            pe->set_type(dns_type_name(a.type));
            pe->set_class_(dns_class_name(a.cls));

            if (a.rdaddress.addr.size() == 4) {
                // IPv4 address.
                std::string addr;
                addr = a.rdaddress.to_ip4_string();
                pe->set_address(addr);
            }
            
            if (a.rdaddress.addr.size() == 16) {
                // IPv6 address.
                std::string addr;
                addr = a.rdaddress.to_ip6_string();
                pe->set_address(addr);
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
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		// FIXME: Confusing
		{ "id", e.id },
		{ "action", "ntp_timestamp" },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "ntp_timestamp", {
			{ "version", e.ts.m_hdr.m_version },
			{ "mode", e.ts.m_hdr.m_mode }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const ntp_control_message& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		// FIXME: Confusing
		{ "id", e.id },
		{ "action", "ntp_control" },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "ntp_control", {
			{ "version", e.ctrl.m_hdr.m_version },
			{ "mode", e.ctrl.m_hdr.m_mode }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const ntp_private_message& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		// FIXME: Confusing
		{ "id", e.id },
		{ "action", "ntp_private" },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "ntp_private", {
			{ "version", e.priv.m_hdr.m_version },
			{ "mode", e.priv.m_hdr.m_mode }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const gre& e, cyberprobe::Event& pe) {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "gre", {
			{ "payload", jsonify(e.payload) },
			{ "next_proto", e.next_proto },
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    if (e.key != 0)
		obj["gre"]["key"] = e.key;
	    if (e.sequence_no != 0)
		obj["gre"]["sequence_number"] = e.sequence_no;
	    return obj;
            */
	}

	void protobufify(const gre_pptp& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "gre_pptp", {
			{ "payload", jsonify(e.payload) },
			{ "next_proto", e.next_proto },
			{ "payload_length", e.payload_length }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    if (e.ack_no != 0)
		obj["gre_pptp"]["acknowledgement_number"] = e.ack_no;
	    if (e.sequence_no != 0)
		obj["gre_pptp"]["sequence_number"] = e.sequence_no;
	    return obj;
            */
	}

	void protobufify(const esp& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "esp", {
			{ "sequence_number", e.sequence },
			{ "payload_length", e.payload_length }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const unrecognised_ip_protocol& e,
                         cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "unrecognised_ip_protocol", {
			{ "payload", jsonify(e.payload) },
			{ "next_proto", e.next_proto },
			{ "payload_length", e.payload_length }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const wlan& e, cyberprobe::Event& pe) 
        {
/*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "wlan", {
			{ "version", e.version },
			{ "type", e.type },
			{ "subtype", e.subtype },
			{ "flags", e.flags },
			{ "protected", e.is_protected },
			{ "filt_addr", e.filt_addr },
			{ "frag_num", e.frag_num },
			{ "seq_num", e.seq_num },
			{ "duration", e.duration }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_unknown& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_unknown", {
			{ "version", e.version },
			{ "content_type", e.content_type },
			{ "length", e.length }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	} 

	static std::string int_to_hex(int n) {
	    std::ostringstream buf;
	    buf << std::hex << n;
	    return buf.str();
	}

	using cipher_suite = cybermon::tls_handshake_protocol::cipher_suite;
	void protobufify(const cipher_suite& suite, cyberprobe::Event& pe) {
            /*
	    if (suite.name == "Unassigned")
		return json(suite.name + "-" + int_to_hex(suite.id));
	    return json(suite.name);
            */
	}

	using cipher_suites = std::vector<cipher_suite>;
	void protobufify(const cipher_suites& suites, cyberprobe::Event& pe) {
            /*
	    json cs = json::array();
	    for(cipher_suites::const_iterator it = suites.begin();
		it != suites.end();
		it++) {
		cs.push_back(jsonify(*it));
	    }
	    return cs;
            */
	}

	using compression_method =
                               cybermon::tls_handshake_protocol::
                               compression_method;
	void protobufify(const compression_method& method, cyberprobe::Event& pe)
        {
            /*
	    if (method.name == "Unassigned")
		return json(method.name + "-" + int_to_hex(method.id));
	    return json(method.name);
            */
	}

	using compression_methods = std::vector<compression_method>;
	void protobufify(const compression_methods methods,
                         cyberprobe::Event& pe)

        {
            /*
		     
	    json cm = json::array();

	    for(compression_methods::const_iterator it = methods.begin();
		it != methods.end();
		it++) {
		cm.push_back(jsonify(*it));
	    }
	    return cm;
            */
	}

	using extension = cybermon::tls_handshake_protocol::extension;
	void protobufify(const extension& ext, cyberprobe::Event& pe)
        {
            /*
	    json obj = {
		{ "name", ext.name },
		{ "length", ext.len },
		{ "type", ext.type },
		{ "data", jsonify(ext.data) }
	    };
	    return obj;*/
	}

	using extensions = std::vector<extension>;
	void protobufify(const extensions& exts, cyberprobe::Event& pe)
        {
            /*
	    json ex = json::array();
	    for(extensions::const_iterator it = exts.begin();
		it != exts.end();
		it++) {
		ex.push_back(jsonify(*it));
	    }
	    return ex;*/
	}

	void protobufify(const tls_client_hello& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_client_hello", {
			{ "version", e.data.version },
			{ "session_id", e.data.sessionID },
			{ "random", {
				{ "random_timestamp", e.data.randomTimestamp },
				{ "data", jsonify(std::begin(e.data.random),
						  std::end(e.data.random)) }
			    }
			},
			{ "cipher_suites", jsonify(e.data.cipherSuites) },
			{ "compression_methods",
			  jsonify(e.data.compressionMethods) },
			{ "extensions", jsonify(e.data.extensions) }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };

	    return obj;
            */
	}

	void protobufify(const tls_server_hello& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_server_hello", {
			{ "version", e.data.version },
			{ "session_id", e.data.sessionID },
			{ "random", {
				{ "random_timestamp", e.data.randomTimestamp },
				{ "data", jsonify(std::begin(e.data.random),
						  std::end(e.data.random)) }
			    }
			},
			{ "cipher_suite", jsonify(e.data.cipherSuite) },
			{ "compression_method",
			  jsonify(e.data.compressionMethod) },
			{ "extensions", jsonify(e.data.extensions) }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}


	void protobufify(const tls_certificates& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json certs = json::array();
	    for(std::vector<std::vector<uint8_t> >::const_iterator it =
		    e.certs.begin();
		it != e.certs.end();
		it++) {
		certs.push_back(jsonify(*it));
	    }

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_certificates", {
			{ "tls", {
				{ "certificates", certs }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	using curve_data = tls_handshake_protocol::curve_data;
	static void protobufify(const std::vector<curve_data>& cd,
                                cyberprobe::Event& pe)
        {
            /*
	    json obj = json::array();
	    for(std::vector<curve_data>::const_iterator it = cd.begin();
		it != cd.end();
		it++) {
		json c = {
		    { "name", it->name },
		    { "value", it->value }
		};
		obj.push_back(c);
	    }
	    return obj;
            */
	}

	using key_exchange = tls_handshake_protocol::key_exchange_data ;
	static void protobufify(const key_exchange& ke, cyberprobe::Event& pe)
        {
            /*
	    if (ke.ecdh) {
		json obj = {
		    { "key_exchange_algorithm", "ec-dh" },
		    { "curve_type", ke.ecdh->curveType },
		    { "curve_metadata", jsonify(ke.ecdh->curveData) },
		    { "public_key", jsonify(ke.ecdh->pubKey) },
		    { "signature_hash_algorithm", ke.ecdh->sigHashAlgo },
		    { "signature_algorithm", ke.ecdh->sigAlgo },
		    { "signature_hash",
		      jsonify(ke.ecdh->hash.begin(), ke.ecdh->hash.end()) }
		};
		return obj;
	    }
	    if (ke.dhrsa) {
		json obj = {
		    { "key_exchange_algorithm", "dh-rsa" },
		    { "prime",
		      jsonify(ke.dhanon->p.begin(), ke.dhanon->p.end()) },
		    { "generator",
		      jsonify(ke.dhanon->g.begin(), ke.dhanon->g.end()) },
		    { "pubkey",
		      jsonify(ke.dhanon->pubKey.begin(),
			      ke.dhanon->pubKey.end()) },
		    { "signature",
		      jsonify(ke.dhrsa->sig.begin(), ke.dhrsa->sig.end()) },
		};
		return obj;
	    }
	    json obj = {
		{ "key_exchange_algorithm", "dh-anon" },
		{ "prime",
		  jsonify(ke.dhanon->p.begin(), ke.dhanon->p.end())
		},
		{ "generator",
		  jsonify(ke.dhanon->g.begin(), ke.dhanon->g.end())
		},
		{ "pubkey",
		  jsonify(ke.dhanon->pubKey.begin(),
			  ke.dhanon->pubKey.end())
		}
	    };
	    return obj;

            */
        }
            

	void protobufify(const tls_server_key_exchange& e,
                         cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_server_key_exchange", {
			{ "tls", jsonify(e.data) }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_server_hello_done& e, cyberprobe::Event& pe)
        {

            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_server_hello_done", {
			{ "tls", json::object() }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_handshake_generic& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_handshake_generic", {
			{ "tls", {
				{ "type", e.type },
				{ "length", e.len }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	using signature_algorithm = tls_handshake_protocol::signature_algorithm;
	void protobufify(const signature_algorithm& sa, cyberprobe::Event& pe)
        {
            /*
	    json obj = {
		{ "hash_algorithm", sa.sigHashAlgo },
		{ "signature_algorithm", sa.sigAlgo }
	    };
	    return obj;
            */
	}

	using signature_algorithms = std::vector<signature_algorithm>;
	void protobufify(const signature_algorithms& sa, cyberprobe::Event& pe)
        {
            /*
	    json arr = json::array();
	    for(signature_algorithms::const_iterator it = sa.begin();
		it != sa.end();
		it++) {
		arr.push_back(jsonify(*it));
	    }
	    return arr;
            */
	}

	void protobufify(const std::vector<std::string>& strs,
                         cyberprobe::Event& pe)
        {
            /*
	    json arr = json::array();
	    for(std::vector<std::string>::const_iterator it = strs.begin();
		it != strs.end();
		it++)
		arr.push_back(*it);
	    return arr;
            */
	}

	void protobufify(const tls_certificate_request& e,
                         cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_certificate_request", {
			{ "tls", {
				{ "cert_types",
				  jsonify(e.data.certTypes) },
				{ "signature_algorithms",
				  jsonify(e.data.sigAlgos) },
				{ "distinguished_names",
				  jsonify(e.data.distinguishedNames) }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_client_key_exchange& e,
                         cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_client_key_exchange", {
			{ "tls", {
				{ "key",
				  jsonify(e.key) }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_certificate_verify& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_certificate_verify", {
			{ "tls", {
				{ "signature_hash_algorithm", e.sig_hash_algo },
				{ "signature_algorithm", e.sig_algo },
				{ "signature", e.sig }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_change_cipher_spec& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_change_cipher_spec", {
			{ "tls", {
				{ "value", e.val }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_handshake_finished& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_handshake_finished", {
			{ "tls", {
				{ "message", jsonify(e.msg) }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_handshake_complete& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_handshake_complete", {
			{ "tls", {
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

	void protobufify(const tls_application_data& e, cyberprobe::Event& pe)
        {
            /*
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "tls_application_data", {
			{ "tls", {
				{ "version", e.version },
				{ "length", e.data.size() }
			    }
			}
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
            */
	}

    };

};

