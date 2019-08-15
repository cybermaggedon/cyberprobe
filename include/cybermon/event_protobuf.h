
#ifndef CYBERMON_EVENT_PROTOBUF_H
#define CYBERMON_EVENT_PROTOBUF_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WITH_PROTOBUF
#include "cyberprobe.pb.h"
#endif

#include <string>

namespace cybermon {

    namespace event {
	
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

        typedef std::string pbuf;

        void protobufify(const connection_up& d, cyberprobe::Event&);
        void protobufify(const connection_down& d, cyberprobe::Event&);
        void protobufify(const trigger_up& d, cyberprobe::Event&);
        void protobufify(const trigger_down& d, cyberprobe::Event&);
        void protobufify(const unrecognised_stream& d, cyberprobe::Event&);
        void protobufify(const unrecognised_datagram& d, cyberprobe::Event&);
        void protobufify(const icmp& d, cyberprobe::Event&);
        void protobufify(const imap& d, cyberprobe::Event&);
        void protobufify(const imap_ssl& d, cyberprobe::Event&);
        void protobufify(const pop3& d, cyberprobe::Event&);
        void protobufify(const pop3_ssl& d, cyberprobe::Event&);
        void protobufify(const rtp& d, cyberprobe::Event&);
        void protobufify(const rtp_ssl& d, cyberprobe::Event&);
        void protobufify(const sip_request& d, cyberprobe::Event&);
        void protobufify(const sip_response& d, cyberprobe::Event&);
        void protobufify(const sip_ssl& d, cyberprobe::Event&);
        void protobufify(const smtp_auth& d, cyberprobe::Event&);
        void protobufify(const smtp_command& d, cyberprobe::Event&);
        void protobufify(const smtp_response& d, cyberprobe::Event&);
        void protobufify(const smtp_data& d, cyberprobe::Event&);
        void protobufify(const http_request& d, cyberprobe::Event&);
        void protobufify(const http_response& d, cyberprobe::Event&);
        void protobufify(const ftp_command& d, cyberprobe::Event&);
        void protobufify(const ftp_response& d, cyberprobe::Event&);
        void protobufify(const dns_message& d, cyberprobe::Event&);
        void protobufify(const ntp_timestamp_message& d, cyberprobe::Event&);
        void protobufify(const ntp_control_message& d, cyberprobe::Event&);
        void protobufify(const ntp_private_message& d, cyberprobe::Event&);
        void protobufify(const gre& d, cyberprobe::Event&);
        void protobufify(const gre_pptp& d, cyberprobe::Event&);
        void protobufify(const esp& d, cyberprobe::Event&);
        void protobufify(const unrecognised_ip_protocol& d, cyberprobe::Event&);
        void protobufify(const wlan& d, cyberprobe::Event&);
        void protobufify(const tls_unknown& d, cyberprobe::Event&);
        void protobufify(const tls_client_hello& d, cyberprobe::Event&);
        void protobufify(const tls_server_hello& d, cyberprobe::Event&);
        void protobufify(const tls_certificates& d, cyberprobe::Event&);
        void protobufify(const tls_server_key_exchange& d, cyberprobe::Event&);
        void protobufify(const tls_server_hello_done& d, cyberprobe::Event&);
        void protobufify(const tls_handshake_generic& d, cyberprobe::Event&);
        void protobufify(const tls_certificate_request& d, cyberprobe::Event&);
        void protobufify(const tls_client_key_exchange& d, cyberprobe::Event&);
        void protobufify(const tls_certificate_verify& d, cyberprobe::Event&);
        void protobufify(const tls_change_cipher_spec& d, cyberprobe::Event&);
        void protobufify(const tls_handshake_finished& d, cyberprobe::Event&);
        void protobufify(const tls_handshake_complete& d, cyberprobe::Event&);
        void protobufify(const tls_application_data& d, cyberprobe::Event&);

	template<class C>
	inline void protobufify(const C& d, pbuf& c) {
            cyberprobe::Event pe;
	    protobufify(d, pe);
            c = "";
            pe.SerializeToString(&c);
        }

    };

};

#endif

