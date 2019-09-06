
#ifndef CYBERPROBE_EVENT_EVENT_IMPLEMENTATIONS_H
#define CYBERPROBE_EVENT_MON_EVENT_IMPLEMENTATIONS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vector>
#include <string>
#include <list>
#include <map>

#include <cyberprobe/protocol/base_context.h>
#include <cyberprobe/protocol/dns_protocol.h>
#include <cyberprobe/protocol/tls_handshake_protocol.h>
#include <cyberprobe/protocol/ntp_protocol.h>
#include <cyberprobe/event/event.h>
#include <cyberprobe/event/event_json.h>

namespace cyberprobe {

    namespace event {

        using pdu = protocol::pdu;
        using pdu_iter = protocol::pdu_iter;
        using context_ptr = protocol::context_ptr;

	class trigger_up : public event {
	public:
	    std::string device;
	    std::string address;
	    trigger_up(const std::string& device,
		       const tcpip::address& addr,
		       const timeval& time) :
		event(TRIGGER_UP, time),
		device(device)
		{
		    addr.to_string(address);
		}
	    virtual ~trigger_up() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    virtual std::string get_device() const { return device; }
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class trigger_down : public event {
	public:
	    std::string device;
	    trigger_down(const std::string& device, const timeval& time) :
		event(TRIGGER_DOWN, time),
		device(device)
		{}
	    virtual ~trigger_down() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    virtual std::string get_device() const { return device; }
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class unrecognised_stream : public protocol_event {
	public:
	    unrecognised_stream(const context_ptr cp,
				pdu_iter s, pdu_iter e,
				const timeval& time, int64_t posn) :
		protocol_event(UNRECOGNISED_STREAM, time, cp),
		position(posn)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~unrecognised_stream() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    int64_t position;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class connection_up : public protocol_event {
	public:
	    connection_up(const context_ptr cp,
			  const timeval& time) :
		protocol_event(CONNECTION_UP, time, cp)
		{
		}
	    virtual ~connection_up() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};
      
	class connection_down : public protocol_event {
	public:
	    connection_down(const context_ptr cp,
                            const timeval& time) :
		protocol_event(CONNECTION_DOWN, time, cp)
		{
		}
	    virtual ~connection_down() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};
      
	class unrecognised_datagram : public protocol_event {
	public:
	    unrecognised_datagram(const context_ptr cp,
				  pdu_iter s, pdu_iter e,
				  const timeval& time) :
		protocol_event(UNRECOGNISED_DATAGRAM, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~unrecognised_datagram() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class icmp : public protocol_event {
	public:
	    icmp(const context_ptr cp, unsigned int type,
		 unsigned int code,
		 pdu_iter s, pdu_iter e,
		 const timeval& time) :
		protocol_event(ICMP, time, cp),
		type(type), code(code)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~icmp() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    unsigned int type;
	    unsigned int code;
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class imap : public protocol_event {
	public:
	    imap(const context_ptr cp,
		 pdu_iter s, pdu_iter e,
		 const timeval& time) :
		protocol_event(IMAP, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~imap() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class imap_ssl : public protocol_event {
	public:
	    imap_ssl(const context_ptr cp,
		     pdu_iter s, pdu_iter e,
		     const timeval& time) :
		protocol_event(IMAP_SSL, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~imap_ssl() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class pop3 : public protocol_event {
	public:
	    pop3(const context_ptr cp,
		 pdu_iter s, pdu_iter e,
		 const timeval& time) :
		protocol_event(POP3, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~pop3() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};
	
	class pop3_ssl : public protocol_event {
	public:
	    pop3_ssl(const context_ptr cp,
		     pdu_iter s, pdu_iter e,
		     const timeval& time) :
		protocol_event(POP3_SSL, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~pop3_ssl() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class rtp : public protocol_event {
	public:
	    rtp(const context_ptr cp,
		pdu_iter s, pdu_iter e,
		const timeval& time) :
		protocol_event(RTP, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~rtp() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class rtp_ssl: public protocol_event {
	public:
	    rtp_ssl(const context_ptr cp,
		    pdu_iter s, pdu_iter e,
		    const timeval& time) :
		protocol_event(RTP_SSL, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~rtp_ssl() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class smtp_auth : public protocol_event {
	public:
	    smtp_auth(const context_ptr cp,
		      pdu_iter s, pdu_iter e,
		      const timeval& time) :
		protocol_event(SMTP_AUTH, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~smtp_auth() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class sip_ssl : public protocol_event {
	public:
	    sip_ssl(const context_ptr cp,
		    pdu_iter s, pdu_iter e,
		    const timeval& time) :
		protocol_event(SIP_SSL, time, cp)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~sip_ssl() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class sip_request : public protocol_event {
	public:
	    sip_request(const context_ptr cp,
			const std::string& method,
			const std::string& from, const std::string& to,
			pdu_iter s, pdu_iter e,
			const timeval& time) :
		protocol_event(SIP_REQUEST, time, cp),
		method(method), from(from), to(to)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~sip_request() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string method;
	    const std::string from;
	    const std::string to;
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class sip_response : public protocol_event {
	public:
	    sip_response(const context_ptr cp, unsigned int code,
			 const std::string& status, const std::string& from,
			 const std::string& to,
			 pdu_iter s, pdu_iter e,
			 const timeval& time) :
		protocol_event(SIP_RESPONSE, time, cp),
		code(code), status(status), from(from), to(to)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~sip_response() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    unsigned int code;
	    const std::string status;
	    const std::string from;
	    const std::string to;
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class http_request : public protocol_event {
	public:
	    http_request(const context_ptr cp,
			 const std::string& method,
			 const std::string& url,
			 const http_hdr_t& hdr,
			 pdu_iter s, pdu_iter e,
			 const timeval& time) :
		protocol_event(HTTP_REQUEST, time, cp),
		method(method), url(url), header(hdr)
		{
		    body.resize(e - s);
		    std::copy(s, e, body.begin());
		}
	    virtual ~http_request() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string method;
	    const std::string url;
	    http_hdr_t header;
	    pdu body;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class http_response : public protocol_event {
	public:
	    http_response(const context_ptr cp, unsigned int code,
			  const std::string& status,
			  const http_hdr_t& hdr,
			  const std::string& url,
			  pdu_iter s, pdu_iter e,
			  const timeval& time) :
		protocol_event(HTTP_RESPONSE, time, cp),
		code(code), status(status), header(hdr), url(url)
		{
		    body.resize(e - s);
		    std::copy(s, e, body.begin());
		}
	    virtual ~http_response() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    unsigned int code;
	    const std::string status;
	    http_hdr_t header;
	    const std::string url;
	    pdu body;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class smtp_command : public protocol_event {
	public:
	    smtp_command(const context_ptr cp,
			 const std::string& command, const timeval& time) :
		protocol_event(SMTP_COMMAND, time, cp),
		command(command)
		{}
	    virtual ~smtp_command() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string command;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class smtp_response : public protocol_event {
	public:
	    smtp_response(const context_ptr cp, int status,
			  const std::list<std::string>& text,
			  const timeval& time) :
		protocol_event(SMTP_RESPONSE, time, cp),
		status(status), text(text)
		{}
	    virtual ~smtp_response() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    int status;
	    const std::list<std::string> text;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class smtp_data : public protocol_event {
	public:
	    smtp_data(const context_ptr cp, const std::string& from,
		      const std::list<std::string>& to,
		      std::vector<unsigned char>::const_iterator s,
		      std::vector<unsigned char>::const_iterator e,
		      const timeval& time) :
		protocol_event(SMTP_DATA, time, cp),
		from(from), to(to)
		{
		    body.resize(e - s);
		    std::copy(s, e, body.begin());
		}
	    virtual ~smtp_data() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string from;
	    const std::list<std::string> to;
	    pdu body;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class ftp_command : public protocol_event {
	public:
	    ftp_command(const context_ptr cp,
			const std::string& command, const timeval& time) :
		protocol_event(FTP_COMMAND, time, cp),
		command(command)
		{
		}
	    virtual ~ftp_command() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string command;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class ftp_response : public protocol_event {
	public:
	    ftp_response(const context_ptr cp, int status,
			 const std::list<std::string>& text,
			 const timeval& time) :
		protocol_event(FTP_RESPONSE, time, cp),
		status(status), text(text)
		{}
	    virtual ~ftp_response() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    int status;
	    const std::list<std::string> text;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class dns_message : public protocol_event {
	public:
	    dns_message(const context_ptr cp,
			const protocol::dns_header& hdr,
			const std::list<protocol::dns_query>& queries,
			const std::list<protocol::dns_rr>& answers,
			const std::list<protocol::dns_rr>& authorities,
			const std::list<protocol::dns_rr>& additional,
			const timeval& time) :
		protocol_event(DNS_MESSAGE, time, cp),
		header(hdr), queries(queries), answers(answers),
		authorities(authorities), additional(additional)
		{}
	    virtual ~dns_message() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    protocol::dns_header header;
	    std::list<protocol::dns_query> queries;
	    std::list<protocol::dns_rr> answers;
	    std::list<protocol::dns_rr> authorities;
	    std::list<protocol::dns_rr> additional;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};
    
	class ntp_timestamp_message : public protocol_event {
	public:
	    ntp_timestamp_message(const context_ptr cp,
				  const protocol::ntp_timestamp& ts,
				  const timeval& time) :
		protocol_event(NTP_TIMESTAMP_MESSAGE, time, cp),
		ts(ts)
		{}
	    virtual ~ntp_timestamp_message() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const protocol::ntp_timestamp ts;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class ntp_control_message : public protocol_event {
	public:
	    ntp_control_message(const context_ptr cp,
				const protocol::ntp_control& ctrl,
				const timeval& time) :
		protocol_event(NTP_CONTROL_MESSAGE, time, cp),
		ctrl(ctrl)
		{}
	    virtual ~ntp_control_message() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const protocol::ntp_control ctrl;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class ntp_private_message : public protocol_event {
	public:
	    ntp_private_message(const context_ptr cp,
				const protocol::ntp_private& priv,
				const timeval& time) :
		protocol_event(NTP_PRIVATE_MESSAGE, time, cp),
		priv(priv)
		{
		}
	    virtual ~ntp_private_message() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const protocol::ntp_private priv;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class gre : public protocol_event {
	public:
	    gre(const context_ptr cp, const std::string& next_proto,
		const uint32_t key, const uint32_t seq_no,
		pdu_iter s, pdu_iter e,
		const timeval& time) :
		protocol_event(GRE_MESSAGE, time, cp),
		next_proto(next_proto), key(key),
		sequence_no(seq_no)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~gre() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string next_proto;
	    const uint32_t key;
	    const uint32_t sequence_no;
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class gre_pptp : public protocol_event {
	public:
	    gre_pptp(const context_ptr cp,
		     const std::string& next_proto,
		     const uint16_t len, const uint16_t c_id,
		     const uint32_t seq_no, const uint32_t ack_no,
		     pdu_iter s, pdu_iter e,
		     const timeval& time) :
		protocol_event(GRE_PPTP_MESSAGE, time, cp),
		next_proto(next_proto), payload_length(len),
		call_id(c_id), sequence_no(seq_no), ack_no(ack_no)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~gre_pptp() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string next_proto;
	    const uint16_t payload_length;
	    const uint16_t call_id;
	    const uint32_t sequence_no;
	    const uint32_t ack_no;
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class esp : public protocol_event {
	public:
	    esp(const context_ptr cp,
		const uint32_t spi, const uint32_t seq, const uint32_t len,
		pdu_iter s, pdu_iter e,
		const timeval& time) :
		protocol_event(ESP, time, cp),
		spi(spi), sequence(seq), payload_length(len)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~esp() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const uint32_t spi;
	    const uint32_t sequence;
	    const uint32_t payload_length;
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class unrecognised_ip_protocol : public protocol_event {
	public:
	    unrecognised_ip_protocol(const context_ptr cp,
				     const uint8_t next_proto,
				     const uint32_t len,
				     pdu_iter s, pdu_iter e,
				     const timeval& time) :
		protocol_event(UNRECOGNISED_IP_PROTOCOL, time, cp),
		next_proto(next_proto), payload_length(len)
		{
		    payload.resize(e - s);
		    std::copy(s, e, payload.begin());
		}
	    virtual ~unrecognised_ip_protocol() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const uint8_t next_proto;
	    const uint32_t payload_length;
	    pdu payload;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class wlan : public protocol_event {
	public:
	    wlan(const context_ptr cp,
		 const uint8_t version, const uint8_t type,
		 const uint8_t subtype, const uint8_t flags,
		 const bool is_protected, const uint16_t duration,
		 const std::string& filt_addr, const uint8_t frag_num,
		 const uint16_t seq_num, const timeval& time) :
		protocol_event(WLAN, time, cp),
		version(version), type(type), subtype(subtype),
		flags(flags), is_protected(is_protected), duration(duration),
		filt_addr(filt_addr), frag_num(frag_num),
		seq_num(seq_num)
		{
		}
	    virtual ~wlan() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const uint8_t version;
	    const uint8_t type;
	    const uint8_t subtype;
	    const uint8_t flags;
	    const bool is_protected;
	    const uint16_t duration;
	    const std::string filt_addr;
	    const uint8_t frag_num;
	    const uint16_t seq_num;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_unknown : public protocol_event {
	public:
	    tls_unknown(const context_ptr cp,
			const std::string& version, const uint8_t content_type,
			const uint16_t length, const timeval& time) :
		protocol_event(TLS_UNKNOWN, time, cp),
		version(version), content_type(content_type),
		length(length)
		{
		}
	    virtual ~tls_unknown() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string version;
	    const uint8_t content_type;
	    const uint16_t length;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_client_hello : public protocol_event {
	public:
	    tls_client_hello(const context_ptr cp,
			     const protocol::tls_handshake_protocol::client_hello_data& data,
			     const timeval& time) :
		protocol_event(TLS_CLIENT_HELLO, time, cp),
		data(data)
		{
		}
	    virtual ~tls_client_hello() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const protocol::tls_handshake_protocol::client_hello_data data;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_server_hello : public protocol_event {
	public:
	    tls_server_hello(const context_ptr cp,
			     const protocol::tls_handshake_protocol::server_hello_data& data,
			     const timeval& time) :
		protocol_event(TLS_SERVER_HELLO, time, cp),
		data(data)
		{
		}
	    virtual ~tls_server_hello() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const protocol::tls_handshake_protocol::server_hello_data data;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_server_hello_done : public protocol_event {
	public:
	    tls_server_hello_done(const context_ptr cp,
				  const timeval& time) :
		protocol_event(TLS_SERVER_HELLO_DONE, time, cp)
		{
		}
	    virtual ~tls_server_hello_done() {}
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_certificates : public protocol_event {
	public:
	    tls_certificates(const context_ptr cp,
			     const std::vector<std::vector<uint8_t>>& crt,
			     const timeval& time) :
		protocol_event(TLS_CERTIFICATES, time, cp),
		certs(crt)
		{
		    certs.reserve(certs.size());
		    certs.insert(certs.end(), crt.begin(), crt.end());
		}
	    virtual ~tls_certificates() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    std::vector<std::vector<uint8_t>> certs;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_server_key_exchange : public protocol_event {
	public:
	    tls_server_key_exchange(const context_ptr cp,
				    const protocol::tls_handshake_protocol::key_exchange_data& data,
				    const timeval& time) :
		protocol_event(TLS_SERVER_KEY_EXCHANGE, time, cp),
		data(data)
		{
		}
	    virtual ~tls_server_key_exchange() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const protocol::tls_handshake_protocol::key_exchange_data data;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_handshake_generic : public protocol_event {
	public:
	    tls_handshake_generic(const context_ptr cp,
				  const uint8_t type, const uint32_t len,
				  const timeval& time) :
		protocol_event(TLS_HANDSHAKE_GENERIC, time, cp),
		type(type), len(len)
		{
		}
	    virtual ~tls_handshake_generic() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const uint8_t type;
	    const uint32_t len;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_certificate_request : public protocol_event {
	public:
	    tls_certificate_request(const context_ptr cp,
				    const protocol::tls_handshake_protocol::certificate_request_data& data,
				    const timeval& time) :
		protocol_event(TLS_CERTIFICATE_REQUEST, time, cp),
		data(data)
		{
		}
	    virtual ~tls_certificate_request() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const protocol::tls_handshake_protocol::certificate_request_data data;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_client_key_exchange : public protocol_event {
	public:
	    tls_client_key_exchange(const context_ptr cp,
				    const std::vector<uint8_t>& key,
				    const timeval& time) :
		protocol_event(TLS_CLIENT_KEY_EXCHANGE, time, cp),
		key(key)
		{
		}
	    virtual ~tls_client_key_exchange() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::vector<uint8_t> key;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_certificate_verify : public protocol_event {
	public:
	    tls_certificate_verify(const context_ptr cp,
				   const uint8_t sig_hash_algo,
				   const uint8_t sig_algo,
				   const std::string& sig,
				   const timeval& time) :
		protocol_event(TLS_CERTIFICATE_VERIFY, time, cp),
		sig_hash_algo(sig_hash_algo),
		sig_algo(sig_algo), sig(sig)
		{
		}
	    virtual ~tls_certificate_verify() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const uint8_t sig_hash_algo;
	    const uint8_t sig_algo;
	    const std::string sig;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_change_cipher_spec : public protocol_event {
	public:
	    tls_change_cipher_spec(const context_ptr cp,
				   const uint8_t val, const timeval& time) :
		protocol_event(TLS_CHANGE_CIPHER_SPEC, time, cp),
		val(val)
		{
		}
	    virtual ~tls_change_cipher_spec() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const uint8_t val;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_handshake_finished : public protocol_event {
	public:
	    tls_handshake_finished(const context_ptr cp,
				   const std::vector<uint8_t>& msg,
				   const timeval& time) :
		protocol_event(TLS_HANDSHAKE_FINISHED, time, cp),
		msg(msg)
		{
		}
	    virtual ~tls_handshake_finished() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::vector<uint8_t> msg;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_handshake_complete : public protocol_event {
	public:
	    tls_handshake_complete(const context_ptr cp,
				   const timeval& time) :
		protocol_event(TLS_HANDSHAKE_COMPLETE, time, cp)
		{
		}
	    virtual ~tls_handshake_complete() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

	class tls_application_data : public protocol_event {
	public:
	    tls_application_data(const context_ptr cp,
				 const std::string& ver,
				 const std::vector<uint8_t>& data,
				 const timeval& time) :
		protocol_event(TLS_APPLICATION_DATA, time, cp),
		version(ver), data(data)
		{
		}
	    virtual ~tls_application_data() {}
	    virtual int get_lua_value(cybermon_lua&, const std::string& name);
	    const std::string version;
	    const std::vector<uint8_t> data;
	    virtual void to_json(std::string& doc) {
		jsonify(*this, doc);
	    }
#ifdef WITH_PROTOBUF
            virtual void to_protobuf(cyberprobe::Event& ev);
#endif
	};

    };

};

#endif

