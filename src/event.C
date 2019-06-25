
#include <cybermon/event.h>
#include <cybermon/engine.h>
#include <cybermon/cybermon-lua.h>
#include <iostream>

using namespace cybermon::event;

std::string protocol_event::get_device() {
    std::string device;
    address trigger_address;
    cybermon::engine::get_root_info(context, device, trigger_address);
    return device;
}

std::string action_names[] = {
    "connection_up",
    "connection_down",
    "trigger_up",
    "trigger_down",
    "unrecognised_stream",
    "unrecognised_datagram",
    "icmp",
    "imap",
    "imap_ssl",
    "pop3",
    "pop3_ssl",
    "rtp",
    "rtp_ssl",
    "sip_request",
    "sip_response",
    "sip_ssl",
    "smtp_auth",
    "smtp_command",
    "smtp_response",
    "smtp_data",
    "http_request",
    "http_response",
    "ftp_command",
    "ftp_response",
    "dns_message",
    "ntp_timestamp_message",
    "ntp_control_message",
    "ntp_private_message",
    "gre_message",
    "gre_pptp_message",
    "esp",
    "unrecognised_ip_protocol",
    "wlan",
    "tls_unknown",
    "tls_client_hello",
    "tls_server_hello",
    "tls_certificates",
    "tls_server_key_exchange",
    "tls_server_hello_done",
    "tls_handshake_generic",
    "tls_certificate_request",
    "tls_client_key_exchange",
    "tls_certificate_verify",
    "tls_change_cipher_spec",
    "tls_handshake_finished",
    "tls_handshake_complete",
    "tls_application_data"
};

std::string& cybermon::event::action2string(action_type a)
{
    return action_names[a];
}

int event::get_lua_value(cybermon_lua& state, const std::string& key)
{

    if (key == "device") {
	state.push(get_device());
	return 1;
    }

    if (key == "action") {
	state.push(get_action());
	return 1;
    }

    if (key == "time") {
	state.push(time);
	return 1;
    }

    if (key == "context") {
	auto eptr = dynamic_cast<protocol_event*>(this);
	if (eptr == 0) {
	    // Not a protocol event, return nil.
	    state.push();
	    return 1;
	}
	state.push(eptr->context);
	return 1;
    }

    // Return nil.
    state.push();
    return 1;
}

int dns_message::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "header") {
	state.push(header);
	return 1;
    }
    if (key == "queries") {
	state.push(queries);
	return 1;
    }
    if (key == "answers") {
	state.push(answers);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int imap::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int imap_ssl::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int pop3::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int pop3_ssl::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int rtp::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int rtp_ssl::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

static void push_http_header(cybermon::cybermon_lua& state,
			     const http_hdr_t& hdr)
{

    state.create_table(0, hdr.size());

    // Loop through header
    for(http_hdr_t::const_iterator it = hdr.begin();
        it != hdr.end();
        it++) {

        // Set table row.
        state.push(it->second.first);
        state.push(it->second.second);
        state.set_table(-3);

    }

}


int http_request::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "method") {
	state.push(method);
	return 1;
    }
    if (key == "url") {
	state.push(url);
	return 1;
    }
    if (key == "header") {
	push_http_header(state, header);
	return 1;
    }
    if (key == "body") {
	state.push(body);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int http_response::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "code") {
	state.push(code);
	return 1;
    }
    if (key == "status") {
	state.push(status);
	return 1;
    }
    if (key == "url") {
	state.push(url);
	return 1;
    }
    if (key == "header") {
	push_http_header(state, header);
	return 1;
    }
    if (key == "body") {
	state.push(body);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int icmp::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "code") {
	state.push(code);
	return 1;
    }
    if (key == "type") {
	state.push(type);
	return 1;
    }
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int trigger_up::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "address") {
	state.push(address);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int trigger_down::get_lua_value(cybermon_lua& state, const std::string& key)
{
    return event::get_lua_value(state, key);
}


int unrecognised_stream::get_lua_value(cybermon_lua& state,
				       const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    if (key == "position") {
	state.push(position);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int unrecognised_datagram::get_lua_value(cybermon_lua& state,
					 const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int connection_up::get_lua_value(cybermon_lua& state, const std::string& key)
{
    return event::get_lua_value(state, key);
}

int connection_down::get_lua_value(cybermon_lua& state, const std::string& key)
{
    return event::get_lua_value(state, key);
}


int sip_request::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "method") {
	state.push(method);
	return 1;
    }
    if (key == "from") {
	state.push(from);
	return 1;
    }
    if (key == "to") {
	state.push(to);
	return 1;
    }
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int sip_response::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "code") {
	state.push(code);
	return 1;
    }
    if (key == "status") {
	state.push(status);
	return 1;
    }
    if (key == "from") {
	state.push(from);
	return 1;
    }
    if (key == "to") {
	state.push(to);
	return 1;
    }
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int sip_ssl::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int smtp_auth::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "data") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int tls_handshake_complete::get_lua_value(cybermon_lua& state,
					  const std::string& key)
{
    return event::get_lua_value(state, key);
}


int smtp_response::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "status") {
	state.push(status);
	return 1;
    }
    if (key == "text") {
	state.push(text);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int tls_certificate_request::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "cert_types") {
	state.create_table(data.certTypes.size(), 0);
	int index = 1;
	for (std::vector<std::string>::const_iterator iter=data.certTypes.begin();
	     iter != data.certTypes.end();
	     ++iter) {
	    state.push(index);
	    state.push(*iter);
	    state.set_table(-3);
	    ++index;
	}
	return 1;
    }
    if (key == "signature_algorithms") {
	state.create_table(data.sigAlgos.size(), 0);
	int index = 1;
	for (std::vector<tls_handshake_protocol::signature_algorithm>::const_iterator iter=data.sigAlgos.begin();
	     iter != data.sigAlgos.end();
	     ++iter) {
	    state.push(index);
	    state.create_table(2,0);
	    state.push("hash_algorithm");
	    state.push(iter->sigHashAlgo);
	    state.set_table(-3);
	    state.push("signature_algorithm");
	    state.push(iter->sigAlgo);
	    state.set_table(-3);
	    state.set_table(-3);
	    ++index;
	}
	return 1;
    }
    if (key == "distinguished_names") {
	state.push(data.distinguishedNames.begin(),
		   data.distinguishedNames.end());
	return 1;
    }
    return event::get_lua_value(state, key);
}


int tls_client_hello::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "version") {
	state.push(data.version);
	return 1;
    }
    if (key == "random_timestamp") {
	state.push(data.randomTimestamp);
	return 1;
    }
    if (key == "random_data") {
	state.push(std::begin(data.random), std::end(data.random));
	return 1;
    }
    if (key == "session_id") {
	state.push(data.sessionID);
	return 1;
    }
    if (key == "cipher_suites") {
	state.create_table(data.cipherSuites.size(), 0);
	int index = 1;
	for (std::vector<tls_handshake_protocol::cipher_suite>::const_iterator iter=data.cipherSuites.begin();
	     iter != data.cipherSuites.end();
	     ++iter) {
	    state.push(index);
	    state.create_table(2,0);
	    state.push("id");
	    state.push(iter->id);
	    state.set_table(-3);
	    state.push("name");
	    state.push(iter->name);
	    state.set_table(-3);
	    state.set_table(-3);
	    ++index;
	}
	return 1;
    }
    if (key == "compression_methods") {
	state.create_table(data.compressionMethods.size(), 0);
	int index = 1;
	for (std::vector<tls_handshake_protocol::compression_method>::const_iterator iter=data.compressionMethods.begin();
	     iter != data.compressionMethods.end();
	     ++iter) {
	    state.push(index);
	    state.create_table(2,0);
	    state.push("id");
	    state.push(iter->id);
	    state.set_table(-3);
	    state.push("name");
	    state.push(iter->name);
	    state.set_table(-3);
	    state.set_table(-3);
	    ++index;
	}
	return 1;
    }
    if (key == "extensions") {
	state.create_table(data.extensions.size(), 0);
	int index = 1;
	for (std::vector<tls_handshake_protocol::extension>::const_iterator iter=data.extensions.begin();
	     iter != data.extensions.end();
	     ++iter) {
	    state.push(index);
	    state.create_table(4,0);
	    state.push("type");
	    state.push(iter->type);
	    state.set_table(-3);
	    state.push("name");
	    state.push(iter->name);
	    state.set_table(-3);
	    state.push("length");
	    state.push(iter->len);
	    state.set_table(-3);
	    state.push("data");
	    state.push(iter->data.begin(), iter->data.end());
	    state.set_table(-3);
	    state.set_table(-3);
	    ++index;
	}
	return 1;
    }
    return event::get_lua_value(state, key);
}

int tls_server_hello::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "version") {
	state.push(data.version);
	return 1;
    }
    if (key == "random_timestamp") {
	state.push(data.randomTimestamp);
	return 1;
    }
    if (key == "random_data") {
	state.push(std::begin(data.random), std::end(data.random));
	return 1;
    }
    if (key == "session_id") {
	state.push(data.sessionID);
	return 1;
    }
    if (key == "cipher_suite") {
	state.create_table(2,0);
	state.push("id");
	state.push(data.cipherSuite.id);
	state.set_table(-3);
	state.push("name");
	state.push(data.cipherSuite.name);
	state.set_table(-3);
	return 1;
    }
    if (key == "compression_method") {
	state.create_table(2,0);
	state.push("id");
	state.push(data.compressionMethod.id);
	state.set_table(-3);
	state.push("name");
	state.push(data.compressionMethod.name);
	state.set_table(-3);
	return 1;
    }
    if (key == "extensions") {
	state.create_table(data.extensions.size(), 0);
	int index = 1;
	for (std::vector<tls_handshake_protocol::extension>::const_iterator iter=data.extensions.begin();
	     iter != data.extensions.end();
	     ++iter) {
	    state.push(index);
	    state.create_table(4,0);
	    state.push("type");
	    state.push(iter->type);
	    state.set_table(-3);
	    state.push("name");
	    state.push(iter->name);
	    state.set_table(-3);
	    state.push("length");
	    state.push(iter->len);
	    state.set_table(-3);
	    state.push("data");
	    state.push(iter->data.begin(), iter->data.end());
	    state.set_table(-3);
	    state.set_table(-3);
	    ++index;
	}
	return 1;
    }
    return event::get_lua_value(state, key);
}


int tls_handshake_generic::get_lua_value(cybermon_lua& state,
					 const std::string& key)
{
    if (key == "type") {
	state.push(type);
	return 1;
    }
    if (key == "length") {
	state.push(len);
	return 1;
    }
    return event::get_lua_value(state, key);
}



int tls_server_key_exchange::get_lua_value(cybermon_lua& state,
					   const std::string& key)
{
    return event::get_lua_value(state, key);
}



int gre::get_lua_value(cybermon_lua& state,
		       const std::string& key)
{
    if (key == "next_proto") {
	state.push(next_proto);
	return 1;
    }
    if (key == "key") {
	state.push(key);
	return 1;
    }
    if (key == "sequence_number") {
	state.push(sequence_no);
	return 1;
    }
    if (key == "payload") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int gre_pptp::get_lua_value(cybermon_lua& state,
			    const std::string& key)
{
    if (key == "next_proto") {
	state.push(next_proto);
	return 1;
    }
    if (key == "call_id") {
	state.push(call_id);
	return 1;
    }
    if (key == "sequence_number") {
	state.push(sequence_no);
	return 1;
    }
    if (key == "acknowledgement_number") {
	state.push(ack_no);
	return 1;
    }
    if (key == "payload_length") {
	state.push(payload_length);
	return 1;
    }
    if (key == "payload") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}



int unrecognised_ip_protocol::get_lua_value(cybermon_lua& state,
					    const std::string& key)
{
    if (key == "next_proto") {
	state.push(next_proto);
	return 1;
    }
    if (key == "payload_length") {
	state.push(payload_length);
	return 1;
    }
    if (key == "payload") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int ntp_private_message::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "header") {
	state.push(priv.m_hdr);
	return 1;
    }
    if (key == "private") {
	state.push(priv);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int ntp_timestamp_message::get_lua_value(cybermon_lua& state,
					 const std::string& key)
{
    if (key == "header") {
	state.push(ts.m_hdr);
	return 1;
    }
    if (key == "timestamp") {
	state.push(ts);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int ntp_control_message::get_lua_value(cybermon_lua& state,
				       const std::string& key)
{
    if (key == "header") {
	state.push(ctrl.m_hdr);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int tls_application_data::get_lua_value(cybermon_lua& state,
					const std::string& key)
{
    if (key == "version") {
	state.push(version);
	return 1;
    }
    if (key == "data") {
	state.push(data);
	return 1;
    }
    return event::get_lua_value(state, key);
}



int ftp_response::get_lua_value(cybermon_lua& state,
				const std::string& key)
{
    if (key == "status") {
	state.push(status);
	return 1;
    }
    if (key == "text") {
	state.push(text);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int ftp_command::get_lua_value(cybermon_lua& state,
			       const std::string& key)
{
    if (key == "command") {
	state.push(command);
	return 1;
    }
    return event::get_lua_value(state, key);
}




int smtp_data::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "from") {
	state.push(from);
	return 1;
    }
    if (key == "to") {
	state.push(to);
	return 1;
    }
    if (key == "data") {
	state.push(body);
	return 1;
    }
    return event::get_lua_value(state, key);
}



int tls_client_key_exchange::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "key") {
	state.push(key.begin(), key.end());
	return 1;
    }
    return event::get_lua_value(state, key);
}




int tls_unknown::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "version") {
	state.push(version);
	return 1;
    }
    if (key == "content_type") {
	state.push(content_type);
	return 1;
    }
    if (key == "length") {
	state.push(length);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int tls_certificate_verify::get_lua_value(cybermon_lua& state,
					  const std::string& key)
{
    if (key == "signature_algorithm") {
	state.create_table(2,0);
	state.push("hash_algorithm");
	state.push(sig_hash_algo);
	state.set_table(-3);
	state.push("signature_algorithm");
	state.push(sig_algo);
	state.set_table(-3);
	return 1;
    }
    if (key == "signature") {
	state.push(sig);
	return 1;
    }
    return event::get_lua_value(state, key);
}



int tls_change_cipher_spec::get_lua_value(cybermon_lua& state,
					  const std::string& key)
{
    if (key == "val") {
	state.push(val);
	return 1;
    }
    return event::get_lua_value(state, key);
}


int tls_certificates::get_lua_value(cybermon_lua& state,
				    const std::string& key)
{
    return event::get_lua_value(state, key);
}


int wlan::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "version") {
	state.push(version);
	return 1;
    }
    if (key == "type") {
	state.push(type);
	return 1;
    }
    if (key == "subtype") {
	state.push(subtype);
	return 1;
    }
    if (key == "flags") {
	state.push(flags);
	return 1;
    }
    if (key == "protected") {
	state.push(is_protected);
	return 1;
    }
    if (key == "duration") {
	state.push(duration);
	return 1;
    }
    if (key == "filt_addr") {
	state.push(filt_addr);
	return 1;
    }
    if (key == "frag_num") {
	state.push(frag_num);
	return 1;
    }
    if (key == "seq_num") {
	state.push(seq_num);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int tls_handshake_finished::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "message") {
	state.push(msg);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int smtp_command::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "command") {
	state.push(command);
	return 1;
    }
    return event::get_lua_value(state, key);
}

int esp::get_lua_value(cybermon_lua& state, const std::string& key)
{
    if (key == "spi") {
	state.push(spi);
	return 1;
    }
    if (key == "sequence_number") {
	state.push(sequence);
	return 1;
    }
    if (key == "payload_length") {
	state.push(payload_length);
	return 1;
    }
    if (key == "payload") {
	state.push(payload);
	return 1;
    }
    return event::get_lua_value(state, key);
}


