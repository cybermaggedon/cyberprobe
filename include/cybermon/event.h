
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

	class event {
	public:
	    action_type action;
	    timeval time;
	    std::string id;
	    event() {}
	    event(const action_type action,
		  const timeval& time) :
		action(action), time(time), id(id) {
	    }
	    virtual ~event() {}
	};

	class trigger_up : public event {
	public:
	    std::string device;
	    std::string address;
	    trigger_up(const std::string& device,
		       const std::string& address,
		       const timeval& time) :
		device(device), address(address),
		event(TRIGGER_UP, time)
		{}
	};

	class trigger_down: public event {
	public:
	    std::string device;
	    trigger_down(const std::string& device, const timeval& time) :
		device(device),
		event(TRIGGER_DOWN, time)
		{}
	};

	class unrecognised_stream : public event {
	public:
	    unrecognised_stream(const cybermon::context_ptr cp,
				cybermon::pdu_iter s, cybermon::pdu_iter e,
				const timeval& time, int64_t posn) :
		context(cp), position(posn),
		event(UNRECOGNISED_STREAM, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	    int64_t position;
	};

	class unrecognised_datagram : public event {
	public:
	    unrecognised_datagram(const cybermon::context_ptr cp,
				  cybermon::pdu_iter s, cybermon::pdu_iter e,
				  const timeval& time) :
		context(cp),
		event(UNRECOGNISED_DATAGRAM, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class icmp : public event {
	public:
	    icmp(const cybermon::context_ptr cp, unsigned int type,
		 unsigned int code,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
		context(cp), type(type), code(code),
		event(ICMP, time)
		{
		    data.resize(e - s);
		    std::copy(s, e, data.begin());
		}
	    cybermon::context_ptr context;
	    unsigned int type;
	    unsigned int code;
	    cybermon::pdu data;
	};

	class imap : public event {
	public:
	    imap(const cybermon::context_ptr cp,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
		context(cp),
		event(IMAP, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class imap_ssl : public event {
	public:
	    imap_ssl(const cybermon::context_ptr cp,
		     cybermon::pdu_iter s, cybermon::pdu_iter e,
		     const timeval& time) :
		context(cp),
		event(IMAP_SSL, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class pop3 : public event {
	public:
	    pop3(const cybermon::context_ptr cp,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
		context(cp), event(POP3, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};
	
	class pop3_ssl : public event {
	public:
	    pop3_ssl(const cybermon::context_ptr cp,
		     cybermon::pdu_iter s, cybermon::pdu_iter e,
		     const timeval& time) :
		context(cp),
		event(POP3_SSL, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class rtp : public event {
	public:
	    rtp(const cybermon::context_ptr cp,
		cybermon::pdu_iter s, cybermon::pdu_iter e,
		const timeval& time) :
		context(cp),
		event(RTP, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class rtp_ssl: public event {
	public:
	    rtp_ssl(const cybermon::context_ptr cp,
		    cybermon::pdu_iter s, cybermon::pdu_iter e,
		    const timeval& time) :
		context(cp),
		event(RTP_SSL, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class smtp_auth : public event {
	public:
	    smtp_auth(const cybermon::context_ptr cp,
		      cybermon::pdu_iter s, cybermon::pdu_iter e,
		      const timeval& time) :
		context(cp),
		event(SMTP_AUTH, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class sip_ssl : public event {
	public:
	    sip_ssl(const cybermon::context_ptr cp,
		    cybermon::pdu_iter s, cybermon::pdu_iter e,
		    const timeval& time) :
		context(cp),
		event(SIP_SSL, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    cybermon::pdu pdu;
	};

	class sip_request : public event {
	public:
	    sip_request(const cybermon::context_ptr cp,
			const std::string& method,
			const std::string& from, const std::string& to,
			cybermon::pdu_iter s, cybermon::pdu_iter e,
			const timeval& time) :
		context(cp), method(method), from(from), to(to),
		event(SIP_REQUEST, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    const std::string method;
	    const std::string from;
	    const std::string to;
	    cybermon::pdu pdu;
	};

	class sip_response : public event {
	public:
	    sip_response(const cybermon::context_ptr cp, unsigned int code,
			 const std::string& status, const std::string& from,
			 const std::string& to,
			 cybermon::pdu_iter s, cybermon::pdu_iter e,
			 const timeval& time) :
		context(cp), code(code), status(status), from(from), to(to),
		event(SIP_RESPONSE, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    unsigned int code;
	    const std::string status;
	    const std::string from;
	    const std::string to;
	    cybermon::pdu pdu;
	};

	class http_request : public event {
	public:
	    http_request(const cybermon::context_ptr cp,
			 const std::string& method,
			 const std::string& url,
			 const http_hdr_t& hdr,
			 cybermon::pdu_iter s, cybermon::pdu_iter e,
			 const timeval& time) :
		context(cp), method(method), url(url), hdr(hdr),
		event(HTTP_REQUEST, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    const std::string method;
	    const std::string url;
	    http_hdr_t hdr;
	    cybermon::pdu pdu;
	};

	class http_response : public event {
	public:
	    http_response(const cybermon::context_ptr cp, unsigned int code,
			  const std::string& status,
			  const http_hdr_t& hdr,
			  const std::string& url,
			  cybermon::pdu_iter s, cybermon::pdu_iter e,
			  const timeval& time) :
		context(cp), code(code), status(status), hdr(hdr), url(url),
		event(HTTP_RESPONSE, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    unsigned int code;
	    const std::string status;
	    http_hdr_t hdr;
	    const std::string url;
	    cybermon::pdu pdu;
	};

	class smtp_command : public event {
	public:
	    smtp_command(const cybermon::context_ptr cp,
			 const std::string& command, const timeval& time) :
		context(cp), command(command),
		event(SMTP_COMMAND, time)
		{}
	    cybermon::context_ptr context;
	    const std::string command;
	};

	class smtp_response : public event {
	public:
	    smtp_response(const cybermon::context_ptr cp, int status,
			  const std::list<std::string>& text,
			  const timeval& time) :
		context(cp), status(status), text(text),
		event(SMTP_RESPONSE, time)
		{}
	    cybermon::context_ptr context;
	    int status;
	    const std::list<std::string> text;
	};

	class smtp_data : public event {
	public:
	    smtp_data(const cybermon::context_ptr cp, const std::string& from,
		      const std::list<std::string>& to,
		      std::vector<unsigned char>::const_iterator s,
		      std::vector<unsigned char>::const_iterator e,
		      const timeval& time) :
		context(cp), from(from), to(to), 
		event(SMTP_DATA, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    const std::string from;
	    const std::list<std::string> to;
	    cybermon::pdu pdu;
	};

	class ftp_command : public event {
	public:
	    ftp_command(const cybermon::context_ptr cp,
			const std::string& command, const timeval& time) :
		context(cp), command(command),
		event(FTP_COMMAND, time)
		{
		}
	    cybermon::context_ptr context;
	    const std::string command;
	};

	class ftp_response : public event {
	public:
	    ftp_response(const cybermon::context_ptr cp, int status,
			 const std::list<std::string>& text,
			 const timeval& time) :
		context(cp), status(status), text(text),
		event(FTP_RESPONSE, time)
		{}
	    cybermon::context_ptr context;
	    int status;
	    const std::list<std::string> text;
	};

	class dns_message : public event {
	public:
	    dns_message(const cybermon::context_ptr cp,
			const cybermon::dns_header hdr,
			const std::list<cybermon::dns_query> queries,
			const std::list<cybermon::dns_rr> answers,
			const std::list<cybermon::dns_rr> authorities,
			const std::list<cybermon::dns_rr> additional,
			const timeval& time) :
		context(cp), hdr(hdr), queries(queries), answers(answers),
		authorities(authorities), additional(additional),
		event(DNS_MESSAGE, time)
		{}
	    cybermon::context_ptr context;
	    cybermon::dns_header hdr;
	    std::list<cybermon::dns_query> queries;
	    std::list<cybermon::dns_rr> answers;
	    std::list<cybermon::dns_rr> authorities;
	    std::list<cybermon::dns_rr> additional;
	};
    
	class ntp_timestamp_message : public event {
	public:
	    ntp_timestamp_message(const cybermon::context_ptr cp,
				  const cybermon::ntp_timestamp& ts,
				  const timeval& time) :
		context(cp), ts(ts),
		event(NTP_TIMESTAMP_MESSAGE, time)
		{}
	    cybermon::context_ptr context;
	    const cybermon::ntp_timestamp ts;
	};

	class ntp_control_message : public event {
	public:
	    ntp_control_message(const cybermon::context_ptr cp,
				const cybermon::ntp_control& ctrl,
				const timeval& time) :
		context(cp), ctrl(ctrl),
		event(NTP_CONTROL_MESSAGE, time)
		{}
	    cybermon::context_ptr context;
	    const cybermon::ntp_control ctrl;
	};

	class ntp_private_message : public event {
	public:
	    ntp_private_message(const cybermon::context_ptr cp,
				const cybermon::ntp_private& priv,
				const timeval& time) :
		context(cp), priv(priv),
		event(NTP_PRIVATE_MESSAGE, time)
		{
		}
	    cybermon::context_ptr context;
	    const cybermon::ntp_private priv;
	};

	class gre : public event {
	public:
	    gre(const cybermon::context_ptr cp, const std::string& next_proto,
		const uint32_t key, const uint32_t seq_no,
		cybermon::pdu_iter s, cybermon::pdu_iter e,
		const timeval& time) :
		context(cp), next_proto(next_proto), key(key),
		sequence_no(seq_no),
		event(GRE_MESSAGE, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    const std::string next_proto;
	    const uint32_t key;
	    const uint32_t sequence_no;
	    cybermon::pdu pdu;
	};

	class gre_pptp : public event {
	public:
	    gre_pptp(const cybermon::context_ptr cp,
		     const std::string& next_proto,
		     const uint16_t len, const uint16_t c_id,
		     const uint32_t seq_no, const uint32_t ack_no,
		     cybermon::pdu_iter s, cybermon::pdu_iter e,
		     const timeval& time) :
		context(cp), next_proto(next_proto), payload_length(len),
		call_id(c_id), sequence_no(seq_no), ack_no(ack_no),
		event(GRE_PPTP_MESSAGE, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    const std::string next_proto;
	    const uint16_t payload_length;
	    const uint16_t call_id;
	    const uint32_t sequence_no;
	    const uint32_t ack_no;
	    cybermon::pdu pdu;
	};

	class esp : public event {
	public:
	    esp(const cybermon::context_ptr cp,
		const uint32_t spi, const uint32_t seq, const uint32_t len,
		cybermon::pdu_iter s, cybermon::pdu_iter e,
		const timeval& time) :
		context(cp), spi(spi), sequence(seq), length(len),
		event(ESP, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    const uint32_t spi;
	    const uint32_t sequence;
	    const uint32_t length;
	    cybermon::pdu pdu;
	};

	class unrecognised_ip_protocol : public event {
	public:
	    unrecognised_ip_protocol(const cybermon::context_ptr cp,
				     const uint8_t next_proto,
				     const uint32_t len,
				     cybermon::pdu_iter s, cybermon::pdu_iter e,
				     const timeval& time) :
		context(cp), next_proto(next_proto), length(len),
		event(UNRECOGNISED_IP_PROTOCOL, time)
		{
		    pdu.resize(e - s);
		    std::copy(s, e, pdu.begin());
		}
	    cybermon::context_ptr context;
	    const uint8_t next_proto;
	    const uint32_t length;
	    cybermon::pdu pdu;
	};

	class wlan : public event {
	public:
	    wlan(const cybermon::context_ptr cp,
		 const uint8_t version, const uint8_t type,
		 const uint8_t subtype, const uint8_t flags,
		 const bool is_protected, const uint16_t duration,
		 const std::string& filt_addr, const uint8_t frag_num,
		 const uint16_t seq_num, const timeval& time) :
		context(cp), version(version), type(type), subtype(subtype),
		flags(flags), is_protected(is_protected), duration(duration),
		filt_addr(filt_addr), frag_num(frag_num),
		seq_num(seq_num),
		event(WLAN, time)
		{
		}
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

	class tls_unknown : public event {
	public:
	    tls_unknown(const cybermon::context_ptr cp,
			const std::string& version, const uint8_t content_type,
			const uint16_t length, const timeval& time) :
		context(cp), version(version), content_type(content_type),
		length(length),
		event(TLS_UNKNOWN, time)
		{
		}
	    cybermon::context_ptr context;
	    const std::string version;
	    const uint8_t content_type;
	    const uint16_t length;
	    cybermon::pdu pdu;
	};

	class tls_client_hello : public event {
	public:
	    tls_client_hello(const cybermon::context_ptr cp,
			     const cybermon::tls_handshake_protocol::client_hello_data& data,
			     const timeval& time)
		: context(cp), data(data),
		  // copy of data is ok because copy constructor is a deep copy
		  event(TLS_CLIENT_HELLO, time)
		{
		}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::client_hello_data data;
	};

	class tls_server_hello : public event {
	public:
	    tls_server_hello(const cybermon::context_ptr cp,
			     const cybermon::tls_handshake_protocol::server_hello_data& data,
			     const timeval& time) :
		context(cp), data(data),
		// copy of data is ok because copy constructor is a deep copy
		event(TLS_SERVER_HELLO, time) 
		{
		}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::server_hello_data data;
	};

	class tls_certificates : public event {
	public:
	    tls_certificates(const cybermon::context_ptr cp,
			     const std::vector<std::vector<uint8_t>>& crt,
			     const timeval& time) :
		context(cp), certs(certs),
		event(TLS_CERTIFICATES, time)
		{
		    certs.reserve(certs.size());
		    certs.insert(certs.end(), crt.begin(), crt.end());
		}
	    cybermon::context_ptr context;
	    std::vector<std::vector<uint8_t>> certs;
	};

	class tls_server_key_exchange : public event {
	public:
	    tls_server_key_exchange(const cybermon::context_ptr cp,
				    const cybermon::tls_handshake_protocol::key_exchange_data& data,
				    const timeval& time) :
		// copy of data is ok because copy constructor is a deep copy
		context(cp), data(data),
		event(TLS_SERVER_KEY_EXCHANGE, time)
		{
		}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::key_exchange_data data;
	};

	class tls_handshake_generic : public event {
	public:
	    tls_handshake_generic(const cybermon::context_ptr cp,
				  const uint8_t type, const uint32_t len,
				  const timeval& time) :
		context(cp), type(type), len(len),
		event(TLS_HANDSHAKE_GENERIC, time)
		{
		}
	    cybermon::context_ptr context;
	    const uint8_t type;
	    const uint32_t len;
	};

	class tls_certificate_request : public event {
	public:
	    tls_certificate_request(const cybermon::context_ptr cp,
				    const cybermon::tls_handshake_protocol::certificate_request_data& data,
				    const timeval& time) :
		// copy of data is ok because copy constructor is a deep copy
		context(cp), data(data),
		event(TLS_CERTIFICATE_REQUEST, time)
		{
		}
	    cybermon::context_ptr context;
	    const cybermon::tls_handshake_protocol::certificate_request_data data;
	};

	class tls_client_key_exchange : public event {
	public:
	    tls_client_key_exchange(const cybermon::context_ptr cp,
				    const std::vector<uint8_t>& key,
				    const timeval& time) :
		context(cp), key(key),
		event(TLS_CLIENT_KEY_EXCHANGE, time)
		{
		}
	    cybermon::context_ptr context;
	    const std::vector<uint8_t> key;
	};

	class tls_certificate_verify : public event {
	public:
	    tls_certificate_verify(const cybermon::context_ptr cp,
				   const uint8_t sig_hash_algo,
				   const uint8_t sig_algo,
				   const std::string& sig,
				   const timeval& time) :
		context(cp), sig_hash_algo(sig_hash_algo),
		sig_algo(sig_algo), sig(sig),
		event(TLS_CERTIFICATE_VERIFY, time)
		{
		}
	    cybermon::context_ptr context;
	    const uint8_t sig_hash_algo;
	    const uint8_t sig_algo;
	    const std::string sig;
	};

	class tls_change_cipher_spec : public event {
	public:
	    tls_change_cipher_spec(const cybermon::context_ptr cp,
				   const uint8_t val, const timeval& time) :
		context(cp), val(val),
		event(TLS_CHANGE_CIPHER_SPEC, time)
		{
		}
	    cybermon::context_ptr context;
	    const uint8_t val;
	};

	class tls_handshake_finished : public event {
	public:
	    tls_handshake_finished(const cybermon::context_ptr cp,
				   const std::vector<uint8_t>& msg,
				   const timeval& time) :
		context(cp), msg(msg),
		event(TLS_HANDSHAKE_FINISHED, time)
		{
		}
	    cybermon::context_ptr context;
	    const std::vector<uint8_t> msg;
	};

	class tls_application_data : public event {
	public:
	    tls_application_data(const cybermon::context_ptr cp,
				 const std::string& ver,
				 const std::vector<uint8_t>& data,
				 const timeval& time) :
		context(cp), version(ver), data(data),
		event(TLS_APPLICATION_DATA, time)
		{
		}
	    cybermon::context_ptr context;
	    const std::string version;
	    const std::vector<uint8_t> data;
	};

    };

};

#endif

