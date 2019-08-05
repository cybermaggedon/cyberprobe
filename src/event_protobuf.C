
#include <cybermon/event_implementations.h>
#include <cybermon/event_protobuf.h>
#include <cybermon/context.h>

#include "cyberprobe.pb.h"

#include <string.h>
#include <string>

#include <google/protobuf/util/time_util.h>

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
	
	void protobufify(const connection_up& e, pbuf& pb) {

            // FIXME: No event!

        }
        
	void protobufify(const connection_down& e, pbuf& pb) {

            // FIXME: No event!

	}

	void protobufify(const trigger_up& e, pbuf& pb) {

            cyberprobe::Event pe;
            pe.set_id(e.id);
            pe.set_action(cyberprobe::Action::trigger_up);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.get_device());

            auto detail = pe.mutable_trigger_up();
            detail->set_address(e.address);

            pe.SerializeToString(&pb);

	}

	void protobufify(const trigger_down& e, pbuf& pb)
        {

            cyberprobe::Event pe;
            pe.set_id(e.id);
            pe.set_action(cyberprobe::Action::trigger_down);
            *(pe.mutable_time()) = 
                google::protobuf::util::TimeUtil::TimevalToTimestamp(e.time);
            pe.set_device(e.get_device());

            auto detail = pe.mutable_trigger_down();

            pe.SerializeToString(&pb);

	}

	static void protobufify_base(const protocol_event& e,
                                     cyberprobe::Event& pe)
        {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

            pe.set_id(e.id);
            pe.set_action(cyberprobe::Action::unrecognised_stream);
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

	void protobufify(const unrecognised_stream& e, cyberprobe::Event& pe)
        {

            protobufify_base(e, pe);
            
            auto detail = pe.mutable_unrecognised_stream();
            detail->set_payload(e.payload.data(), e.payload.size());
            detail->set_position(e.position);

	}

	void protobufify(const unrecognised_datagram& e,
                         cyberprobe::Event& pe)
        {

            protobufify_base(e, pe);

            auto detail = pe.mutable_unrecognised_datagram();
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const icmp& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe);

            auto detail = pe.mutable_icmp();
            detail->set_type(e.type);
            detail->set_code(e.code);
            detail->set_payload(e.payload.data(), e.payload.size());

	}

	void protobufify(const imap& e, cyberprobe::Event& pe) {

            protobufify_base(e, pe);

            auto detail = pe.mutable_imap();
            detail->set_payload(e.payload.data(), e.payload.size());

	}
/*
	void protobufify(const imap_ssl& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	void protobufify(const pop3& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	void protobufify(const pop3_ssl& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	void protobufify(const rtp& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	void protobufify(const rtp_ssl& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	void protobufify(const sip_request& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const sip_response& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const sip_ssl& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
		{ "action", e.get_action() },
		{ "device", e.get_device() },
		{ "time", jsonify(e.time) },
		{ "payload", jsonify(e.payload) },
		{ "src", src },
		{ "dest", dest }
	    };
	    return obj;
	}

	void protobufify(const smtp_auth& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const smtp_command& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const smtp_response& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const smtp_data& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const http_request& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    std::map<std::string, std::string> hdr;
	    for(http_hdr_t::const_iterator it = e.header.begin();
		it != e.header.end();
		it++)
		hdr[it->second.first] = it->second.second;
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const http_response& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    std::map<std::string, std::string> hdr;
	    for(http_hdr_t::const_iterator it = e.header.begin();
		it != e.header.end();
		it++)
		hdr[it->second.first] = it->second.second;
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const ftp_command& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const ftp_response& e, pbuf& pb) {
	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);
	    json obj = {
		{ "id", e.id },
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

	void protobufify(const dns_message& e, pbuf& pb) {

	    std::list<std::string> src, dest;
	    get_addresses(e.context, src, dest);

	    json obj = {
		{ "id", e.id },
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

	void protobufify(const ntp_timestamp_message& e, pbuf& pb) {
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
	}

	void protobufify(const ntp_control_message& e, pbuf& pb) {
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
	}

	void protobufify(const ntp_private_message& e, pbuf& pb) {
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
	}

	void protobufify(const gre& e, pbuf& pb) {
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
	}

	void protobufify(const gre_pptp& e, pbuf& pb) {
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
	}

	void protobufify(const esp& e, pbuf& pb) {
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
	}

	void protobufify(const unrecognised_ip_protocol& e, pbuf& pb) {
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
	}

	void protobufify(const wlan& e, pbuf& pb) {
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
	}

	void protobufify(const tls_unknown& e, pbuf& pb) {
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
	} 

	static std::string int_to_hex(int n) {
	    std::ostringstream buf;
	    buf << std::hex << n;
	    return buf.str();
	}

	using cipher_suite = cybermon::tls_handshake_protocol::cipher_suite;
	void protobufify(const cipher_suite& suite, pbuf& pb) {
	    if (suite.name == "Unassigned")
		return json(suite.name + "-" + int_to_hex(suite.id));
	    return json(suite.name);
	}

	using cipher_suites = std::vector<cipher_suite>;
	void protobufify(const cipher_suites& suites, pbuf& pb) {
	    json cs = json::array();
	    for(cipher_suites::const_iterator it = suites.begin();
		it != suites.end();
		it++) {
		cs.push_back(jsonify(*it));
	    }
	    return cs;

	}

	using compression_method =
                               cybermon::tls_handshake_protocol::compression_method;
	void protobufify(const compression_method& method, pbuf& pb) {
	    if (method.name == "Unassigned")
		return json(method.name + "-" + int_to_hex(method.id));
	    return json(method.name);
	}

	using compression_methods = std::vector<compression_method>;
	void protobufify(const compression_methods methods, pbuf& pb) {
		     
	    json cm = json::array();

	    for(compression_methods::const_iterator it = methods.begin();
		it != methods.end();
		it++) {
		cm.push_back(jsonify(*it));
	    }
	    return cm;
	}

	using extension = cybermon::tls_handshake_protocol::extension;
	void protobufify(const extension& ext, pbuf& pb) {
	    json obj = {
		{ "name", ext.name },
		{ "length", ext.len },
		{ "type", ext.type },
		{ "data", jsonify(ext.data) }
	    };
	    return obj;
	}

	using extensions = std::vector<extension>;
	void protobufify(const extensions& exts, pbuf& pb) {
	    json ex = json::array();
	    for(extensions::const_iterator it = exts.begin();
		it != exts.end();
		it++) {
		ex.push_back(jsonify(*it));
	    }
	    return ex;
	}

	void protobufify(const tls_client_hello& e, pbuf& pb) {
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
	}

	void protobufify(const tls_server_hello& e, pbuf& pb) {
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
	}


	void protobufify(const tls_certificates& e, pbuf& pb) {
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
	}

	using curve_data = tls_handshake_protocol::curve_data;
	static void protobufify(const std::vector<curve_data>& cd, pbuf& pb) {
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
	static void protobufify(const key_exchange& ke, pbuf& pb) {
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
	}

	void protobufify(const tls_server_key_exchange& e, pbuf& pb) {
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
	}

	void protobufify(const tls_server_hello_done& e, pbuf& pb) {
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
	}

	void protobufify(const tls_handshake_generic& e, pbuf& pb) {
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
	}

	using signature_algorithm = tls_handshake_protocol::signature_algorithm;
	void protobufify(const signature_algorithm& sa, pbuf& pb) {
	    json obj = {
		{ "hash_algorithm", sa.sigHashAlgo },
		{ "signature_algorithm", sa.sigAlgo }
	    };
	    return obj;
	}

	using signature_algorithms = std::vector<signature_algorithm>;
	void protobufify(const signature_algorithms& sa, pbuf& pb) {
	    json arr = json::array();
	    for(signature_algorithms::const_iterator it = sa.begin();
		it != sa.end();
		it++) {
		arr.push_back(jsonify(*it));
	    }
	    return arr;
	}

	void protobufify(const std::vector<std::string>& strs, pbuf& pb) {
	    json arr = json::array();
	    for(std::vector<std::string>::const_iterator it = strs.begin();
		it != strs.end();
		it++)
		arr.push_back(*it);
	    return arr;
	}

	void protobufify(const tls_certificate_request& e, pbuf& pb) {
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
	}

	void protobufify(const tls_client_key_exchange& e, pbuf& pb) {
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
	}

	void protobufify(const tls_certificate_verify& e, pbuf& pb) {
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
	}

	void protobufify(const tls_change_cipher_spec& e, pbuf& pb) {
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
	}

	void protobufify(const tls_handshake_finished& e, pbuf& pb) {
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
	}

	void protobufify(const tls_handshake_complete& e, pbuf& pb) {
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
	}

	void protobufify(const tls_application_data& e, pbuf& pb) {
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
	}
*/
    };

};

