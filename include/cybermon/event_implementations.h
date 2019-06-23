
#ifndef CYBERMON_EVENT_IMPLEMENTATIONS_H
#define CYBERMON_EVENT_IMPLEMENTATIONS_H

#include <vector>
#include <string>
#include <list>
#include <map>

#include <cybermon/base_context.h>
#include <cybermon/dns_protocol.h>
#include <cybermon/tls_handshake_protocol.h>
#include <cybermon/ntp_protocol.h>
#include <cybermon/event.h>

namespace cybermon {

    namespace event {

	class trigger_up : public event {
	public:
	    std::string device;
	    const tcpip::address& address;
	    trigger_up(const std::string& device,
		       const tcpip::address& address,
		       const timeval& time) :
		device(device), address(address),
		event(TRIGGER_UP, time)
		{}
	    virtual ~trigger_up() {}
	    virtual std::string get_device() { return device; }
	};

	class trigger_down: public event {
	public:
	    std::string device;
	    trigger_down(const std::string& device, const timeval& time) :
		device(device),
		event(TRIGGER_DOWN, time)
		{}
	    virtual ~trigger_down() {}
	    virtual std::string get_device() { return device; }
	};

	class unrecognised_stream : public protocol_event {
	public:
	    unrecognised_stream(const cybermon::context_ptr cp,
				cybermon::pdu_iter s, cybermon::pdu_iter e,
				const timeval& time, int64_t posn) :
		position(posn),
		protocol_event(UNRECOGNISED_STREAM, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~unrecognised_stream() {}
	    cybermon::pdu pdu;
	    int64_t position;
	};

	class connection_up : public protocol_event {
	public:
	    connection_up(const cybermon::context_ptr cp,
			  const timeval& time) :
		protocol_event(CONNECTION_UP, time, cp)
		{
		}
	    virtual ~connection_up() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};
      
	class connection_down : public protocol_event {
	public:
	    connection_down(const cybermon::context_ptr cp,
			  const timeval& time) :
		protocol_event(CONNECTION_DOWN, time, cp)
		{
		}
	    virtual ~connection_down() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};
      
	class unrecognised_datagram : public protocol_event {
	public:
	    unrecognised_datagram(const cybermon::context_ptr cp,
				  cybermon::pdu_iter s, cybermon::pdu_iter e,
				  const timeval& time) :
		protocol_event(UNRECOGNISED_DATAGRAM, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~unrecognised_datagram() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class icmp : public protocol_event {
	public:
	    icmp(const cybermon::context_ptr cp, unsigned int type,
		 unsigned int code,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
		type(type), code(code),
		protocol_event(ICMP, time, cp)
		{
		    data.resize(e - s);
		    std::copy(s, e, data.begin());
		}
	    virtual ~icmp() {}
	    cybermon::context_ptr context;
	    unsigned int type;
	    unsigned int code;
	    cybermon::pdu data;
	};

	class imap : public protocol_event {
	public:
	    imap(const cybermon::context_ptr cp,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
		context(cp),
		protocol_event(IMAP, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~imap() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class imap_ssl : public protocol_event {
	public:
	    imap_ssl(const cybermon::context_ptr cp,
		     cybermon::pdu_iter s, cybermon::pdu_iter e,
		     const timeval& time) :
		context(cp),
		protocol_event(IMAP_SSL, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~imap_ssl() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class pop3 : public protocol_event {
	public:
	    pop3(const cybermon::context_ptr cp,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
		protocol_event(POP3, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~pop3() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};
	
	class pop3_ssl : public protocol_event {
	public:
	    pop3_ssl(const cybermon::context_ptr cp,
		     cybermon::pdu_iter s, cybermon::pdu_iter e,
		     const timeval& time) :
		context(cp),
		protocol_event(POP3_SSL, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~pop3_ssl() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class rtp : public protocol_event {
	public:
	    rtp(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e,
		const timeval& time) :
		context(cp),
		protocol_event(RTP, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~rtp() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class rtp_ssl: public protocol_event {
	public:
	    rtp_ssl(const cybermon::context_ptr cp,
		    cybermon::pdu_iter s, cybermon::pdu_iter e,
		    const timeval& time) :
		context(cp),
		protocol_event(RTP_SSL, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~rtp_ssl() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class smtp_auth : public protocol_event {
	public:
	    smtp_auth(const cybermon::context_ptr cp,
		      cybermon::pdu_iter s, cybermon::pdu_iter e,
		      const timeval& time) :
		context(cp),
		protocol_event(SMTP_AUTH, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~smtp_auth() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class sip_ssl : public protocol_event {
	public:
	    sip_ssl(const cybermon::context_ptr cp,
		    cybermon::pdu_iter s, cybermon::pdu_iter e,
		    const timeval& time) :
		context(cp),
		protocol_event(SIP_SSL, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~sip_ssl() {}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class sip_request : public protocol_event {
	public:
	    sip_request(const cybermon::context_ptr cp,
			const std::string& method,
			const std::string& from, const std::string& to,
			cybermon::pdu_iter s, cybermon::pdu_iter e,
			const timeval& time) :
		method(method), from(from), to(to),
		protocol_event(SIP_REQUEST, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~sip_request() {}
	    cybermon::context_ptr context;
	    const std::string method;
	    const std::string from;
	    const std::string to;
	    cybermon::pdu pdu;
	};

	class sip_response : public protocol_event {
	public:
	    sip_response(const cybermon::context_ptr cp, unsigned int code,
			 const std::string& status, const std::string& from,
			 const std::string& to,
			 cybermon::pdu_iter s, cybermon::pdu_iter e,
			 const timeval& time) :
		code(code), status(status), from(from), to(to),
		protocol_event(SIP_RESPONSE, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~sip_response() {}
	    cybermon::context_ptr context;
	    unsigned int code;
	    const std::string status;
	    const std::string from;
	    const std::string to;
	    cybermon::pdu pdu;
	};

	class http_request : public protocol_event {
	public:
	    http_request(const cybermon::context_ptr cp,
			 const std::string& method,
			 const std::string& url,
			 const http_hdr_t& hdr,
			 cybermon::pdu_iter s, cybermon::pdu_iter e,
			 const timeval& time) :
		method(method), url(url), hdr(hdr),
		protocol_event(HTTP_REQUEST, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~http_request() {}
	    cybermon::context_ptr context;
	    const std::string method;
	    const std::string url;
	    http_hdr_t hdr;
	    cybermon::pdu pdu;
	};

	class http_response : public protocol_event {
	public:
	    http_response(const cybermon::context_ptr cp, unsigned int code,
			  const std::string& status,
			  const http_hdr_t& hdr,
			  const std::string& url,
			  cybermon::pdu_iter s, cybermon::pdu_iter e,
			  const timeval& time) :
		code(code), status(status), hdr(hdr), url(url),
		protocol_event(HTTP_RESPONSE, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~http_response() {}
	    cybermon::context_ptr context;
	    unsigned int code;
	    const std::string status;
	    http_hdr_t hdr;
	    const std::string url;
	    cybermon::pdu pdu;
	};

	class smtp_command : public protocol_event {
	public:
	    smtp_command(const cybermon::context_ptr cp,
			 const std::string& command, const timeval& time) :
		command(command),
		protocol_event(SMTP_COMMAND, time, cp)
		{}
	    cybermon::context_ptr context;
	    const std::string command;
	};

	class smtp_response : public protocol_event {
	public:
	    smtp_response(const cybermon::context_ptr cp, int status,
			  const std::list<std::string>& text,
			  const timeval& time) :
		status(status), text(text),
		protocol_event(SMTP_RESPONSE, time, cp)
		{}
	    virtual ~smtp_response() {}
	    cybermon::context_ptr context;
	    int status;
	    const std::list<std::string> text;
	};

	class smtp_data : public protocol_event {
	public:
	    smtp_data(const cybermon::context_ptr cp, const std::string& from,
		      const std::list<std::string>& to,
		      std::vector<unsigned char>::const_iterator s,
		      std::vector<unsigned char>::const_iterator e,
		      const timeval& time) :
		from(from), to(to), 
		protocol_event(SMTP_DATA, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~smtp_data() {}
	    cybermon::context_ptr context;
	    const std::string from;
	    const std::list<std::string> to;
	    cybermon::pdu pdu;
	};

	class ftp_command : public protocol_event {
	public:
	    ftp_command(const cybermon::context_ptr cp,
			const std::string& command, const timeval& time) :
		command(command),
		protocol_event(FTP_COMMAND, time, cp)
		{
		}
	    virtual ~ftp_command() {}
	    cybermon::context_ptr context;
	    const std::string command;
	};

	class ftp_response : public protocol_event {
	public:
	    ftp_response(const cybermon::context_ptr cp, int status,
			 const std::list<std::string>& text,
			 const timeval& time) :
		status(status), text(text),
		protocol_event(FTP_RESPONSE, time, cp)
		{}
	    virtual ~ftp_response() {}
	    cybermon::context_ptr context;
	    int status;
	    const std::list<std::string> text;
	};

	class dns_message : public protocol_event {
	public:
	    dns_message(const cybermon::context_ptr cp,
			const cybermon::dns_header& hdr,
			const std::list<cybermon::dns_query>& queries,
			const std::list<cybermon::dns_rr>& answers,
			const std::list<cybermon::dns_rr>& authorities,
			const std::list<cybermon::dns_rr>& additional,
			const timeval& time) :
		hdr(hdr), queries(queries), answers(answers),
		authorities(authorities), additional(additional),
		protocol_event(DNS_MESSAGE, time, cp)
		{}
	    virtual ~dns_message() {}
	    cybermon::context_ptr context;
	    cybermon::dns_header hdr;
	    std::list<cybermon::dns_query> queries;
	    std::list<cybermon::dns_rr> answers;
	    std::list<cybermon::dns_rr> authorities;
	    std::list<cybermon::dns_rr> additional;
	};
    
	class ntp_timestamp_message : public protocol_event {
	public:
	    ntp_timestamp_message(const cybermon::context_ptr cp,
				  const cybermon::ntp_timestamp& ts,
				  const timeval& time) :
		ts(ts),
		protocol_event(NTP_TIMESTAMP_MESSAGE, time, cp)
		{}
	    virtual ~ntp_timestamp_message() {}
	    cybermon::context_ptr context;
	    const cybermon::ntp_timestamp ts;
	};

	class ntp_control_message : public protocol_event {
	public:
	    ntp_control_message(const cybermon::context_ptr cp,
				const cybermon::ntp_control& ctrl,
				const timeval& time) :
		ctrl(ctrl),
		protocol_event(NTP_CONTROL_MESSAGE, time, cp)
		{}
	    virtual ~ntp_control_message() {}
	    cybermon::context_ptr context;
	    const cybermon::ntp_control ctrl;
	};

	class ntp_private_message : public protocol_event {
	public:
	    ntp_private_message(const cybermon::context_ptr cp,
				const cybermon::ntp_private& priv,
				const timeval& time) :
		priv(priv),
		protocol_event(NTP_PRIVATE_MESSAGE, time, cp)
		{
		}
	    virtual ~ntp_private_message() {}
	    cybermon::context_ptr context;
	    const cybermon::ntp_private priv;
	};

	class gre : public protocol_event {
	public:
	    gre(const cybermon::context_ptr cp, const std::string& next_proto,
		const uint32_t key, const uint32_t seq_no,
		cybermon::pdu_iter s, cybermon::pdu_iter e,
		const timeval& time) :
		next_proto(next_proto), key(key),
		sequence_no(seq_no),
		protocol_event(GRE_MESSAGE, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~gre() {}
	    cybermon::context_ptr context;
	    const std::string next_proto;
	    const uint32_t key;
	    const uint32_t sequence_no;
	    cybermon::pdu pdu;
	};

	class gre_pptp : public protocol_event {
	public:
	    gre_pptp(const cybermon::context_ptr cp,
		     const std::string& next_proto,
		     const uint16_t len, const uint16_t c_id,
		     const uint32_t seq_no, const uint32_t ack_no,
		     cybermon::pdu_iter s, cybermon::pdu_iter e,
		     const timeval& time) :
		next_proto(next_proto), payload_length(len),
		call_id(c_id), sequence_no(seq_no), ack_no(ack_no),
		protocol_event(GRE_PPTP_MESSAGE, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~gre_pptp() {}
	    cybermon::context_ptr context;
	    const std::string next_proto;
	    const uint16_t payload_length;
	    const uint16_t call_id;
	    const uint32_t sequence_no;
	    const uint32_t ack_no;
	    cybermon::pdu pdu;
	};

	class esp : public protocol_event {
	public:
	    esp(const cybermon::context_ptr cp,
		const uint32_t spi, const uint32_t seq, const uint32_t len,
		cybermon::pdu_iter s, cybermon::pdu_iter e,
		const timeval& time) :
		spi(spi), sequence(seq), length(len),
		protocol_event(ESP, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~esp() {}
	    cybermon::context_ptr context;
	    const uint32_t spi;
	    const uint32_t sequence;
	    const uint32_t length;
	    cybermon::pdu pdu;
	};

	class unrecognised_ip_protocol : public protocol_event {
	public:
	    unrecognised_ip_protocol(const cybermon::context_ptr cp,
				     const uint8_t next_proto,
				     const uint32_t len,
				     cybermon::pdu_iter s, cybermon::pdu_iter e,
				     const timeval& time) :
		next_proto(next_proto), length(len),
		protocol_event(UNRECOGNISED_IP_PROTOCOL, time, cp)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    virtual ~unrecognised_ip_protocol() {}
	    cybermon::context_ptr context;
	    const uint8_t next_proto;
	    const uint32_t length;
	    cybermon::pdu pdu;
	};

	class wlan : public protocol_event {
	public:
	    wlan(const cybermon::context_ptr cp,
		 const uint8_t version, const uint8_t type,
		 const uint8_t subtype, const uint8_t flags,
		 const bool is_protected, const uint16_t duration,
		 const std::string& filt_addr, const uint8_t frag_num,
		 const uint16_t seq_num, const timeval& time) :
		version(version), type(type), subtype(subtype),
		flags(flags), is_protected(is_protected), duration(duration),
		filt_addr(filt_addr), frag_num(frag_num),
		seq_num(seq_num),
		protocol_event(WLAN, time, cp)
		{
		}
	    virtual ~wlan() {}
	    cybermon::context_ptr context;
	    const uint8_t version;
	    const uint8_t type;
	    const uint8_t subtype;
	    const uint8_t flags;
	    const bool is_protected;
	    const uint16_t duration;
	    const std::string filt_addr;
	    const uint8_t frag_num;
	    const uint16_t seq_num;
	};

	class tls_unknown : public protocol_event {
	public:
	    tls_unknown(const cybermon::context_ptr cp,
			const std::string& version, const uint8_t content_type,
			const uint16_t length, const timeval& time) :
		version(version), content_type(content_type),
		length(length),
		protocol_event(TLS_UNKNOWN, time, cp)
		{
		}
	    virtual ~tls_unknown() {}
	    cybermon::context_ptr context;
	    const std::string version;
	    const uint8_t content_type;
	    const uint16_t length;
	    cybermon::pdu pdu;
	};

	class tls_client_hello : public protocol_event {
	public:
	    tls_client_hello(const cybermon::context_ptr cp,
			     const cybermon::tls_handshake_protocol::client_hello_data& data,
			     const timeval& time)
		: data(data),
		  // copy of data is ok because copy constructor is a deep copy
		  protocol_event(TLS_CLIENT_HELLO, time, cp)
		{
		}
	    virtual ~tls_client_hello() {}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::client_hello_data data;
	};

	class tls_server_hello : public protocol_event {
	public:
	    tls_server_hello(const cybermon::context_ptr cp,
			     const cybermon::tls_handshake_protocol::server_hello_data& data,
			     const timeval& time) :
		data(data),
		// copy of data is ok because copy constructor is a deep copy
		protocol_event(TLS_SERVER_HELLO, time, cp)
		{
		}
	    virtual ~tls_server_hello() {}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::server_hello_data data;
	};

	class tls_server_hello_done : public protocol_event {
	public:
	    tls_server_hello_done(const cybermon::context_ptr cp,
				  const timeval& time) :
		// copy of data is ok because copy constructor is a deep copy
		protocol_event(TLS_SERVER_HELLO_DONE, time, cp)
		{
		}
	    virtual ~tls_server_hello_done() {}
	    cybermon::context_ptr context;
	};

	class tls_certificates : public protocol_event {
	public:
	    tls_certificates(const cybermon::context_ptr cp,
			     const std::vector<std::vector<uint8_t>>& crt,
			     const timeval& time) :
		certs(certs),
		protocol_event(TLS_CERTIFICATES, time, cp)
		{
		    certs.reserve(certs.size());
		    certs.insert(certs.end(), crt.begin(), crt.end());
		}
	    virtual ~tls_certificates() {}
	    cybermon::context_ptr context;
	    std::vector<std::vector<uint8_t>> certs;
	};

	class tls_server_key_exchange : public protocol_event {
	public:
	    tls_server_key_exchange(const cybermon::context_ptr cp,
				    const cybermon::tls_handshake_protocol::key_exchange_data& data,
				    const timeval& time) :
		// copy of data is ok because copy constructor is a deep copy
		data(data),
		protocol_event(TLS_SERVER_KEY_EXCHANGE, time, cp)
		{
		}
	    virtual ~tls_server_key_exchange() {}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::key_exchange_data data;
	};

	class tls_handshake_generic : public protocol_event {
	public:
	    tls_handshake_generic(const cybermon::context_ptr cp,
				  const uint8_t type, const uint32_t len,
				  const timeval& time) :
		type(type), len(len),
		protocol_event(TLS_HANDSHAKE_GENERIC, time, cp)
		{
		}
	    virtual ~tls_handshake_generic() {}
	    cybermon::context_ptr context;
	    const uint8_t type;
	    const uint32_t len;
	};

	class tls_certificate_request : public protocol_event {
	public:
	    tls_certificate_request(const cybermon::context_ptr cp,
				    const cybermon::tls_handshake_protocol::certificate_request_data& data,
				    const timeval& time) :
		// copy of data is ok because copy constructor is a deep copy
		data(data),
		protocol_event(TLS_CERTIFICATE_REQUEST, time, cp)
		{
		}
	    virtual ~tls_certificate_request() {}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::certificate_request_data data;
	};

	class tls_client_key_exchange : public protocol_event {
	public:
	    tls_client_key_exchange(const cybermon::context_ptr cp,
				    const std::vector<uint8_t>& key,
				    const timeval& time) :
		key(key),
		protocol_event(TLS_CLIENT_KEY_EXCHANGE, time, cp)
		{
		}
	    virtual ~tls_client_key_exchange() {}
	    cybermon::context_ptr context;
	    const std::vector<uint8_t> key;
	};

	class tls_certificate_verify : public protocol_event {
	public:
	    tls_certificate_verify(const cybermon::context_ptr cp,
				   const uint8_t sig_hash_algo,
				   const uint8_t sig_algo,
				   const std::string& sig,
				   const timeval& time) :
		sig_hash_algo(sig_hash_algo),
		sig_algo(sig_algo), sig(sig),
		protocol_event(TLS_CERTIFICATE_VERIFY, time, cp)
		{
		}
	    virtual ~tls_certificate_verify() {}
	    cybermon::context_ptr context;
	    const uint8_t sig_hash_algo;
	    const uint8_t sig_algo;
	    const std::string sig;
	};

	class tls_change_cipher_spec : public protocol_event {
	public:
	    tls_change_cipher_spec(const cybermon::context_ptr cp,
				   const uint8_t val, const timeval& time) :
		val(val),
		protocol_event(TLS_CHANGE_CIPHER_SPEC, time, cp)
		{
		}
	    virtual ~tls_change_cipher_spec() {}
	    cybermon::context_ptr context;
	    const uint8_t val;
	};

	class tls_handshake_finished : public protocol_event {
	public:
	    tls_handshake_finished(const cybermon::context_ptr cp,
				   const std::vector<uint8_t>& msg,
				   const timeval& time) :
		msg(msg),
		protocol_event(TLS_HANDSHAKE_FINISHED, time, cp)
		{
		}
	    virtual ~tls_handshake_finished() {}
	    cybermon::context_ptr context;
	    const std::vector<uint8_t> msg;
	};

	class tls_handshake_complete : public protocol_event {
	public:
	    tls_handshake_complete(const cybermon::context_ptr cp,
				   const timeval& time) :
		protocol_event(TLS_HANDSHAKE_COMPLETE, time, cp)
		{
		}
	    virtual ~tls_handshake_complete() {}
	    cybermon::context_ptr context;
	};

	class tls_application_data : public protocol_event {
	public:
	    tls_application_data(const cybermon::context_ptr cp,
				 const std::string& ver,
				 const std::vector<uint8_t>& data,
				 const timeval& time) :
		version(ver), data(data),
		protocol_event(TLS_APPLICATION_DATA, time, cp)
		{
		}
	    virtual ~tls_application_data() {}
	    cybermon::context_ptr context;
	    const std::string version;
	    const std::vector<uint8_t> data;
	};

    };

};

#endif

