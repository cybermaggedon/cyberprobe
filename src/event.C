
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
    return event::get_lua_value(state, key);
}


int sip_response::get_lua_value(cybermon_lua& state, const std::string& key)
{
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
    return event::get_lua_value(state, key);
}


int tls_client_hello::get_lua_value(cybermon_lua& state, const std::string& key)
{
    return event::get_lua_value(state, key);
}



int tls_handshake_generic::get_lua_value(cybermon_lua& state,
					 const std::string& key)
{
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
    return event::get_lua_value(state, key);
}

int gre_pptp::get_lua_value(cybermon_lua& state,
			    const std::string& key)
{
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
    return event::get_lua_value(state, key);
}




int tls_unknown::get_lua_value(cybermon_lua& state, const std::string& key)
{
    return event::get_lua_value(state, key);
}


int tls_certificate_verify::get_lua_value(cybermon_lua& state,
					  const std::string& key)
{
    return event::get_lua_value(state, key);
}



int tls_change_cipher_spec::get_lua_value(cybermon_lua& state,
					  const std::string& key)
{
    return event::get_lua_value(state, key);
}


int tls_certificates::get_lua_value(cybermon_lua& state,
				    const std::string& key)
{
    return event::get_lua_value(state, key);
}


int wlan::get_lua_value(cybermon_lua& state, const std::string& key)
{
    return event::get_lua_value(state, key);
}

int tls_handshake_finished::get_lua_value(cybermon_lua& state, const std::string& key)
{
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
    return event::get_lua_value(state, key);
}


