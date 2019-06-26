
#ifndef CYBERMON_EVENT_H
#define CYBERMON_EVENT_H

#include <vector>
#include <string>
#include <list>
#include <map>

#include <cybermon/base_context.h>
#include <cybermon/dns_protocol.h>
#include <cybermon/tls_handshake_protocol.h>
#include <cybermon/ntp_protocol.h>

namespace cybermon {

    class cybermon_lua;

    namespace event {    

	typedef std::map<std::string, std::pair<std::string,std::string> > 
	http_hdr_t;
    
	enum action_type {
	    CONNECTION_UP,
	    CONNECTION_DOWN,
	    TRIGGER_UP,
	    TRIGGER_DOWN,
	    UNRECOGNISED_STREAM,
	    UNRECOGNISED_DATAGRAM,
	    ICMP,
	    IMAP,
	    IMAP_SSL,
	    POP3,
	    POP3_SSL,
	    RTP,
	    RTP_SSL,
	    SIP_REQUEST,
	    SIP_RESPONSE,
	    SIP_SSL,
	    SMTP_AUTH,
	    SMTP_COMMAND,
	    SMTP_RESPONSE,
	    SMTP_DATA,
	    HTTP_REQUEST,
	    HTTP_RESPONSE,
	    FTP_COMMAND,
	    FTP_RESPONSE,
	    DNS_MESSAGE,
	    NTP_TIMESTAMP_MESSAGE,
	    NTP_CONTROL_MESSAGE,
	    NTP_PRIVATE_MESSAGE,
	    GRE_MESSAGE,
	    GRE_PPTP_MESSAGE,
	    ESP,
	    UNRECOGNISED_IP_PROTOCOL,
	    WLAN,
	    TLS_UNKNOWN,
	    TLS_CLIENT_HELLO,
	    TLS_SERVER_HELLO,
	    TLS_CERTIFICATES,
	    TLS_SERVER_KEY_EXCHANGE,
	    TLS_SERVER_HELLO_DONE,
	    TLS_HANDSHAKE_GENERIC,
	    TLS_CERTIFICATE_REQUEST,
	    TLS_CLIENT_KEY_EXCHANGE,
	    TLS_CERTIFICATE_VERIFY,
	    TLS_CHANGE_CIPHER_SPEC,
	    TLS_HANDSHAKE_FINISHED,
	    TLS_HANDSHAKE_COMPLETE,
	    TLS_APPLICATION_DATA
	};

	std::string& action2string(action_type a);

	class event {
	public:
	    action_type action;
	    timeval time;
	    event() {}
	    event(const action_type action,
		  const timeval& time) :
		action(action), time(time)
		{
		}
	    virtual ~event() {}
	    virtual std::string get_device() const = 0;
	    virtual std::string& get_action() const {
		return action2string(action);
	    }
	    virtual int get_lua_value(cybermon::cybermon_lua&,
				      const std::string& name) const;
	    virtual void to_json(std::string& doc) const {
		doc == "{}";
	    }
	};

	class protocol_event : public event {
	public:
	    protocol_event(const action_type action,
			   const timeval& time,
			   context_ptr cp) :
		event(action, time), context(cp)
		{
		}
	    virtual ~protocol_event() {}
	    cybermon::context_ptr context;
	    virtual std::string get_device() const;
	};

    };

};

#endif

