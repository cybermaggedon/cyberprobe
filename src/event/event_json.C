
//FIXME: No ID present!

#include <cyberprobe/event/event_implementations.h>
#include <cyberprobe/event/event_json.h>
#include <cyberprobe/protocol/context.h>
#include <nlohmann/json.h>

#include <string.h>
#include <string>

#include <base64/base64.h>

using json = nlohmann::json;

using namespace cyberprobe::protocol;
using namespace cyberprobe::event;

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

	json jsonify(const std::vector<unsigned char>& b) {
	    std::string s = base64::encode(b.begin(), b.end());
	    return json(s);
	}

	template<typename iter>
	json jsonify(iter s, iter e) {
	    std::string str = base64::encode(s, e);
	    return json(str);
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

	json jsonify(const address& addr) {
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

        static void apply_base(const protocol_event& e, json& obj,
                               std::string action)
        {
            obj["id"] = e.id;
            obj["action"] = action;
            obj["device"] = e.device;
            obj["time"] = jsonify(e.time);
            if (e.network != "")
                obj["network"] = e.network;

            if (e.direc == FROM_TARGET)
                obj["origin"] = "device";
            else if (e.direc == TO_TARGET)
                obj["origin"] = "network";

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

            obj["src"] = src;
            obj["dest"] = dest;
	                
        }
	
	json jsonify(const connection_up& e) {
	    json obj;
            apply_base(e, obj, "connected_up");
	    return obj;
	}

	json jsonify(const connection_down& e) {
	    json obj;
            apply_base(e, obj, "connected_down");
	    return obj;
	}

	json jsonify(const trigger_up& e) {

	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "address", e.address }
	    };

	    return obj;
	}

	json jsonify(const trigger_down& e) {

	    json obj  {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "time", jsonify(e.time) }
	    };

	    return obj;
	}

	json jsonify(const unrecognised_stream& e) {
	    json obj;
            apply_base(e, obj, "unrecognised_stream");
            obj["unrecognised_stream"] = {
                { "payload", jsonify(e.payload) },
                { "position", e.position }
            };
            return obj;
	}

	json jsonify(const unrecognised_datagram& e) {
	    json obj;
            apply_base(e, obj, "unrecognised_datagram");
            obj["unrecognised_datagram"] = {
                { "payload", jsonify(e.payload) }
            };
            return obj;
	}

	json jsonify(const icmp& e) {
            json obj;
            apply_base(e, obj, "icmp");
            obj["icmp"] = {
                { "code", int(e.code) },
                { "type", int(e.type) },
                { "payload", jsonify(e.payload) }      
            };
            return obj;
	}

	json jsonify(const imap& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const imap_ssl& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const pop3& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const pop3_ssl& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const rtp& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const rtp_ssl& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const sip_request& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) },
                { "method", e.method },
		{ "from", e.from },
		{ "to", e.to }
            };
	    return obj;
	}

	json jsonify(const sip_response& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) },
		{ "code", e.code },
		{ "status", e.status },
		{ "from", e.from },
		{ "to", e.to }
            };
	    return obj;
	}

	json jsonify(const sip_ssl& e) {
           json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const smtp_auth& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) }
            };
	    return obj;
	}

	json jsonify(const smtp_command& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "command", e.command }
            };
	    return obj;
	}

	json jsonify(const smtp_response& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "status", e.status },
                { "text", e.text }
            };
	    return obj;
	}

	json jsonify(const smtp_data& e) {
            json obj;
            apply_base(e, obj, e.get_action());
                 obj[e.get_action()] = {
                     { "from", e.from },
                     { "to", e.to },
                     { "body", std::string(e.body.begin(), e.body.end()) }
                 };
     	    return obj;
     	}

     	json jsonify(const http_request& e) {
	    std::map<std::string, std::string> hdr;
	    for(http_hdr_t::const_iterator it = e.header.begin();
		it != e.header.end();
		it++)
		hdr[it->second.first] = it->second.second;
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
		{ "method", e.method },
                { "header", hdr }
            };
            obj["url"] = e.url;

	    if (e.body.size() > 0)
		obj[e.get_action()]["body"] = jsonify(e.body);

	    return obj;
	}

	json jsonify(const http_response& e) {
	    std::map<std::string, std::string> hdr;
	    for(http_hdr_t::const_iterator it = e.header.begin();
		it != e.header.end();
		it++)
		hdr[it->second.first] = it->second.second;
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
			{ "status", e.status },
			{ "code", e.code },
			{ "header", hdr },
			{ "body", jsonify(e.body) }
            };
            obj["url"] = e.url;

	    return obj;
	}

	json jsonify(const ftp_command& e) {
       json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "command", e.command }
            };
	    return obj;
	}

	json jsonify(const ftp_response& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "status", e.status },
                { "text", e.text }
            };
	    return obj;
	}

	json jsonify(const dns_message& e) {
            json obj;
            apply_base(e, obj, e.get_action());

	    std::string type;
	    if (e.header.qr == 0)
		type = "query";
	    else
		type = "response";

	    json q = json::array();;
	    for(std::list<dns_query>::const_iterator it =
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
	    for(std::list<dns_rr>::const_iterator it2 =
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

	    obj[e.get_action()] = {
		{ "query", q },
		{ "answer", a },
		{ "type", type }
	    };

	    return obj;
	}

	json jsonify(const ntp_timestamp_message& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "version", e.ts.m_hdr.m_version },
                { "mode", e.ts.m_hdr.m_mode }
            };
	    return obj;
	}

	json jsonify(const ntp_control_message& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj["ntp_control"] = {
                { "version", e.ctrl.m_hdr.m_version },
                { "mode", e.ctrl.m_hdr.m_mode }
            };
	    return obj;
	}

	json jsonify(const ntp_private_message& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj["ntp_private"] = {
                { "version", e.priv.m_hdr.m_version },
                { "mode", e.priv.m_hdr.m_mode }
            };
	    return obj;
	}

	json jsonify(const gre& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) },
                { "next_proto", e.next_proto }
            };
	    return obj;
	}

	json jsonify(const gre_pptp& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) },
                { "next_proto", e.next_proto },
                { "payload_length", e.payload_length }
            };
	    if (e.ack_no != 0)
		obj[e.get_action()]["acknowledgement_number"] = e.ack_no;
	    if (e.sequence_no != 0)
		obj[e.get_action()]["sequence_number"] = e.sequence_no;
	    return obj;
	}

	json jsonify(const esp& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "sequence_number", e.sequence },
                { "payload_length", e.payload_length }
            };
	    return obj;
	}

	json jsonify(const unrecognised_ip_protocol& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "payload", jsonify(e.payload) },
                { "next_proto", e.next_proto },
                { "payload_length", e.payload_length }
            };
	    return obj;
	}

	json jsonify(const wlan& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "version", e.version },
                { "type", e.type },
                { "subtype", e.subtype },
                { "flags", e.flags },
                { "protected", e.is_protected },
                { "filt_addr", e.filt_addr },
                { "frag_num", e.frag_num },
                { "seq_num", e.seq_num },
                { "duration", e.duration }
            };
	    return obj;
	}

	json jsonify(const tls_unknown& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "version", e.version },
                { "content_type", e.content_type },
                { "length", e.length }
            };
	    return obj;
	} 

	static std::string int_to_hex(int n) {
	    std::ostringstream buf;
	    buf << std::hex << n;
	    return buf.str();
	}

	using cipher_suite = tls_handshake_protocol::cipher_suite;
	json jsonify(const cipher_suite& suite) {
	    if (suite.name == "Unassigned")
		return json(suite.name + "-" + int_to_hex(suite.id));
	    return json(suite.name);
	}

	using cipher_suites = std::vector<cipher_suite>;
	json jsonify(const cipher_suites& suites) {
	    json cs = json::array();
	    for(cipher_suites::const_iterator it = suites.begin();
		it != suites.end();
		it++) {
		cs.push_back(jsonify(*it));
	    }
	    return cs;
	}

	using compression_method =
                               tls_handshake_protocol::
                               compression_method;
	json jsonify(const compression_method& method) {
	    if (method.name == "Unassigned")
		return json(method.name + "-" + int_to_hex(method.id));
	    return json(method.name);
	}

	using compression_methods = std::vector<compression_method>;
	json jsonify(const compression_methods methods) {
		     
	    json cm = json::array();

	    for(compression_methods::const_iterator it = methods.begin();
		it != methods.end();
		it++) {
		cm.push_back(jsonify(*it));
	    }
	    return cm;
	}

	using extension = tls_handshake_protocol::extension;
	json jsonify(const extension& ext) {
	    json obj = {
		{ "name", ext.name },
		{ "length", ext.len },
		{ "type", ext.type },
		{ "data", jsonify(ext.data) }
	    };
	    return obj;
	}

	using extensions = std::vector<extension>;
	json jsonify(const extensions& exts) {
	    json ex = json::array();
	    for(extensions::const_iterator it = exts.begin();
		it != exts.end();
		it++) {
		ex.push_back(jsonify(*it));
	    }
	    return ex;
	}

	json jsonify(const tls_client_hello& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
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
            };
	    return obj;
	}

	json jsonify(const tls_server_hello& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
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
            };
	    return obj;
	}


	json jsonify(const tls_certificates& e) {

	    json certs = json::array();
	    for(std::vector<std::vector<uint8_t> >::const_iterator it =
		    e.certs.begin();
		it != e.certs.end();
		it++) {
		certs.push_back(jsonify(*it));
	    }

            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "certificates", certs }
                    }
                }
            };
	    return obj;
	}

	using curve_data = tls_handshake_protocol::curve_data;
	static json jsonify(const std::vector<curve_data>& cd) {
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
	}

	using key_exchange = tls_handshake_protocol::key_exchange_data ;
	static json jsonify(const key_exchange& ke) {
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
		      jsonify(ke.dhrsa->p.begin(), ke.dhrsa->p.end()) },
		    { "generator",
		      jsonify(ke.dhrsa->g.begin(), ke.dhrsa->g.end()) },
		    { "pubkey",
		      jsonify(ke.dhrsa->pubKey.begin(),
			      ke.dhrsa->pubKey.end()) },
		    { "signature",
		      jsonify(ke.dhrsa->sig.begin(), ke.dhrsa->sig.end()) },
		};
		return obj;
	    }
	    if (ke.dhanon) {
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
	    }
	    return json();
	}

	json jsonify(const tls_server_key_exchange& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", jsonify(e.data) }
            };
	    return obj;
	}

	json jsonify(const tls_server_hello_done& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", json::object() }
	    };
	    return obj;
	}

	json jsonify(const tls_handshake_generic& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "type", e.type },
                        { "length", e.len }
                    }
                }
            };
	    return obj;
	}

	using signature_algorithm = tls_handshake_protocol::signature_algorithm;
	json jsonify(const signature_algorithm& sa) {
	    json obj = {
		{ "hash_algorithm", sa.sigHashAlgo },
		{ "signature_algorithm", sa.sigAlgo }
	    };
	    return obj;
	}

	using signature_algorithms = std::vector<signature_algorithm>;
	json jsonify(const signature_algorithms& sa) {
	    json arr = json::array();
	    for(signature_algorithms::const_iterator it = sa.begin();
		it != sa.end();
		it++) {
		arr.push_back(jsonify(*it));
	    }
	    return arr;
	}

	json jsonify(const std::vector<std::string>& strs) {
	    json arr = json::array();
	    for(std::vector<std::string>::const_iterator it = strs.begin();
		it != strs.end();
		it++)
		arr.push_back(*it);
	    return arr;
	}

	json jsonify(const tls_certificate_request& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "cert_types", jsonify(e.data.certTypes) },
                        { "signature_algorithms", jsonify(e.data.sigAlgos) },
                        { "distinguished_names",
                          jsonify(e.data.distinguishedNames) }
                    }
                }
            };
	    return obj;
	}

	json jsonify(const tls_client_key_exchange& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "key", jsonify(e.key) }
                    }
                }
            };
	    return obj;
	}

	json jsonify(const tls_certificate_verify& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "signature_hash_algorithm", e.sig_hash_algo },
                        { "signature_algorithm", e.sig_algo },
                        { "signature", e.sig }
                    }
                }
            };
	    return obj;
	}

	json jsonify(const tls_change_cipher_spec& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "value", e.val }
                    }
                }
            };
	    return obj;
	}

	json jsonify(const tls_handshake_finished& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "message", jsonify(e.msg) }
                    }
                }
            };
	    return obj;
	}

	json jsonify(const tls_handshake_complete& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                    }
                }
            };
	    return obj;
	}

	json jsonify(const tls_application_data& e) {
            json obj;
            apply_base(e, obj, e.get_action());
            obj[e.get_action()] = {
                { "tls", {
                        { "version", e.version },
                        { "length", e.data.size() }
                    }
                }
            };
	    return obj;
	}

    };

};

