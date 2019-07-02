
#ifndef CYBERMON_EVENT_JSON_H
#define CYBERMON_EVENT_JSON_H

#include <string>

#include <json.h>

namespace cybermon {

    namespace event {


	using json = nlohmann::json;
	
	class connection_up;
	class connection_down;
	class trigger_up;
	class trigger_down;
	class unrecognised_stream;
	class unrecognised_datagram;
	class icmp;
	class imap;
	class imap_ssl;
	class pop3;
	class pop3_ssl;
	class rtp;
	class rtp_ssl;
	class sip_request;
	class sip_response;
	class sip_ssl;
	class smtp_auth;
	class smtp_command;
	class smtp_response;
	class smtp_data;
	class http_request;
	class http_response;
	class ftp_command;
	class ftp_response;
	class dns_message;
	class ntp_timestamp_message;
	class ntp_control_message;
	class ntp_private_message;
	class gre;
	class gre_pptp;
	class esp;
	class unrecognised_ip_protocol;
	class wlan;
	class tls_unknown;
	class tls_client_hello;
	class tls_server_hello;
	class tls_certificates;
	class tls_server_key_exchange;
	class tls_server_hello_done;
	class tls_handshake_generic;
	class tls_certificate_request;
	class tls_client_key_exchange;
	class tls_certificate_verify;
	class tls_change_cipher_spec;
	class tls_handshake_finished;
	class tls_handshake_complete;
	class tls_application_data;

	json jsonify(const connection_up& d);
	json jsonify(const connection_down& d);
	json jsonify(const trigger_up& d);
	json jsonify(const trigger_down& d);
	json jsonify(const unrecognised_stream& d);
	json jsonify(const unrecognised_datagram& d);
	json jsonify(const icmp& d);
	json jsonify(const imap& d);
	json jsonify(const imap_ssl& d);
	json jsonify(const pop3& d);
	json jsonify(const pop3_ssl& d);
	json jsonify(const rtp& d);
	json jsonify(const rtp_ssl& d);
	json jsonify(const sip_request& d);
	json jsonify(const sip_response& d);
	json jsonify(const sip_ssl& d);
	json jsonify(const smtp_auth& d);
	json jsonify(const smtp_command& d);
	json jsonify(const smtp_response& d);
	json jsonify(const smtp_data& d);
	json jsonify(const http_request& d);
	json jsonify(const http_response& d);
	json jsonify(const ftp_command& d);
	json jsonify(const ftp_response& d);
	json jsonify(const dns_message& d);
	json jsonify(const ntp_timestamp_message& d);
	json jsonify(const ntp_control_message& d);
	json jsonify(const ntp_private_message& d);
	json jsonify(const gre& d);
	json jsonify(const gre_pptp& d);
	json jsonify(const esp& d);
	json jsonify(const unrecognised_ip_protocol& d);
	json jsonify(const wlan& d);
	json jsonify(const tls_unknown& d);
	json jsonify(const tls_client_hello& d);
	json jsonify(const tls_server_hello& d);
	json jsonify(const tls_certificates& d);
	json jsonify(const tls_server_key_exchange& d);
	json jsonify(const tls_server_hello_done& d);
	json jsonify(const tls_handshake_generic& d);
	json jsonify(const tls_certificate_request& d);
	json jsonify(const tls_client_key_exchange& d);
	json jsonify(const tls_certificate_verify& d);
	json jsonify(const tls_change_cipher_spec& d);
	json jsonify(const tls_handshake_finished& d);
	json jsonify(const tls_handshake_complete& d);
	json jsonify(const tls_application_data& d);
	

	template<class C>
	inline void jsonify(const C& d, std::string& doc) {
	    json obj = jsonify(d);
	    doc = obj.dump();
        }

    };

};

#endif

