
#include <cybermon/event_implementations.h>
#include <cybermon/event_json.h>
#include <cybermon/context.h>

#include <string.h>

#include <json.h>
#include <base64.h>

using json = nlohmann::json;

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

	json jsonify(const std::vector<unsigned char>& b) {
	    std::string s = base64_encode(b.begin(), b.end());
	    return json(s);
	}

	json jsonify(const timeval& time) {
	    char t[256];

	    // Convert time (seconds) to struct tm
	    struct tm* tmv = gmtime(&time.tv_sec);
	    if (tmv == 0)
		throw std::runtime_error("Not a time");

	    // Format time in seconds
	    if (strftime(t, 256, "%Y-%m-%dT%H:%M:%S", tmv) == 0)
		throw std::runtime_error("strftime fail");

	    // Add milliseconds.
	    sprintf(t + strlen(t), ".%03dZ", int(time.tv_usec / 1000));

	    return json(t);
	}

	json jsonify(const cybermon::address& addr) {
	    if (addr.addr.size() == 4)
		return json(addr.to_ip4_string());
	    if (addr.addr.size() == 16)
		return json(addr.to_ip6_string());
	    return json("");
	}

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
	
	json jsonify(const connection_up& e) {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    
	    json obj  {
		// FIXME: Annoying.
		{ "action", "connected_up" },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const connection_down& e) {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
    
	    json obj  {
		// FIXME: Annoying.
		{ "action", "connected_down" },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest }
	    };

	    return obj;
	}

	json jsonify(const trigger_up& e) {

	    json obj = {
		{ "address", e.address },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) }
	    };

	    return obj;
	}

	json jsonify(const trigger_down& e) {

	    json obj  {
		{ "action", e.get_action() },
		{ "time", jsonify(e.time) }
	    };

	    return obj;
	}

	json jsonify(const unrecognised_stream& e) {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "unrecognised_stream", {
			{ "payload", jsonify(e.payload) },
			{ "position", e.position },
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const unrecognised_datagram& e) {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "unrecognised_datagram", {
			{ "payload", jsonify(e.payload) },
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const icmp& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "icmp", {
			{ "code", int(e.code) },
			{ "type", int(e.type) },
			{ "payload", jsonify(e.payload) }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const imap& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const imap_ssl& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const pop3& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const pop3_ssl& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const rtp& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const rtp_ssl& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const sip_request& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest },
		{ "method", e.method },
		{ "from", e.from },
		{ "to", e.to }
	    };
	    return obj;
	}

	json jsonify(const sip_response& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest },
		{ "code", e.code },
		{ "status", e.status },
		{ "from", e.from },
		{ "to", e.to }
	    };
	    return obj;
	}

	json jsonify(const sip_ssl& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const smtp_auth& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
                { "smtp_auth", {
			{ "payload", jsonify(e.payload) }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const smtp_command& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest },
		{ "smtp_command", {
			{ "command", e.command }
		    }
		}
	    };
	    return obj;
	}

	json jsonify(const smtp_response& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest },
		{ "smtp_response", {
			{ "status", e.status },
			{ "text", e.text }
		    }
		}
	    };
	    return obj;
	}

	json jsonify(const smtp_data& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest },
		{ "smtp_data", {
			{ "from", e.from },
			{ "to", e.to },
			{ "body", std::string(e.body.begin(), e.body.end()) }
		    }
		}
	    };
	    return obj;
	}

	json jsonify(const http_request& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    std::map<std::string, std::string> hdr;
	    for(http_hdr_t::const_iterator it = e.header.begin();
		it != e.header.end();
		it++)
		hdr[it->second.first] = it->second.second;
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest },
		{ "url", e.url },
		{ "http_request", {
			{ "method", e.method },
			{ "header", hdr },
		    }
		}
	    };

	    if (e.body.size() > 0)
		obj["http_request"]["body"] = jsonify(e.body);

	    return obj;
	}

	json jsonify(const http_response& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    std::map<std::string, std::string> hdr;
	    for(http_hdr_t::const_iterator it = e.header.begin();
		it != e.header.end();
		it++)
		hdr[it->second.first] = it->second.second;
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest },
		{ "url", e.url },
		{ "http_response", {
			{ "status", e.status },
			{ "code", e.code },
			{ "header", hdr },
			{ "body", jsonify(e.body) }
		    }
		}
	    };

	    return obj;
	}

	json jsonify(const ftp_command& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "ftp_command", {
			{ "command", e.command }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const ftp_response& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "ftp_response", {
			{ "status", e.status },
			{ "text", e.text }
		    }
		},
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	json jsonify(const dns_message& e) {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "src", src },
		{ "dest", dest }
	    };

	    std::string type;
	    if (e.header.qr == 0)
		type = "query";
	    else
		type = "response";

	    json q = json::array();;
	    for(std::list<cybermon::dns_query>::const_iterator it =
		    e.queries.begin();
		it != e.queries.end();
		it++) {
		json o = {
		    { "name", it->name },
		    { "class", dns_class_name(it->cls) },
		    { "type", dns_type_name(it->type) }
		};
		q.push_back(o);
	    }

	    json a = json::array();
	    for(std::list<cybermon::dns_rr>::const_iterator it2 =
		    e.answers.begin();
		it2 != e.answers.end();
		it2++) {

		json o = {
		    { "name", it2->name },
		    { "class", dns_class_name(it2->cls) },
		    { "type", dns_type_name(it2->type) }
		};
	
		if (it2->rdaddress.addr.size() != 0) {
	    
		    if (it2->rdaddress.addr.size() == 4) {
			// IPv4 address.
			o["address"] = it2->rdaddress.to_ip4_string();
		    }
		    if (it2->rdaddress.addr.size() == 16) {
			// IPv6 address.
			o["address"] = it2->rdaddress.to_ip6_string();
		    }

		}

		if (it2->rdname != "")
		    o["name"] = it2->rdname;

		a.push_back(o);
	    }

	    obj["dns_message"] = {
		{ "query", q },
		{ "answer", a },
		{ "type", type }
	    };

	    return obj;
	}

	json jsonify(const ntp_timestamp_message& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		// FIXME: Confusing
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
	}

	json jsonify(const ntp_control_message& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		// FIXME: Confusing
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
	}

	json jsonify(const ntp_private_message& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		// FIXME: Confusing
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
	}

	json jsonify(const gre& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
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
	}

	json jsonify(const gre_pptp& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
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
	}

	json jsonify(const esp& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
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
	}

	json jsonify(const unrecognised_ip_protocol& e) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
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
	}

	json jsonify(const wlan& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_unknown& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_client_hello& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_server_hello& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_certificates& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_server_key_exchange& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_server_hello_done& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_handshake_generic& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_certificate_request& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_client_key_exchange& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_certificate_verify& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_change_cipher_spec& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_handshake_finished& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_handshake_complete& e) {
	    json obj;
	    return obj;
	}

	json jsonify(const tls_application_data& e) {
	    json obj;
	    return obj;
	}

    };

};

