/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

 qargs. Part of new queue implementation to address frequent cybermon
 crash caused due to limitation of lua threading.


****************************************************************************/

#ifndef CYBERMON_QARGS_H_
#define CYBERMON_QARGS_H_

#include <cybermon/event.h>
#include <cybermon/engine.h>
#include <cybermon/tls_handshake_protocol.h>

/*
 * args classes for different protocols
 */
class qargs {

public:
    //Constructor
    qargs() {
    }

    //Destructor
    virtual ~qargs() {
    }

    //enum to use in cybermon_qreader to find out which cybermon lua function to call
    enum call_type {
	connection_up,
	connection_down,
	trigger_up,
	trigger_down,
	unrecognised_stream,
	unrecognised_datagram,
	icmp,
	imap,
	imap_ssl,
	pop3,
	pop3_ssl,
	rtp,
	rtp_ssl,

	sip_request,
	sip_response,
	sip_ssl,
	smtp_auth,
	smtp_command,
	smtp_response,
	smtp_data,
	http_request,
	http_response,
	ftp_command,
	ftp_response,
	dns_message,
	ntp_timestamp_message,
	ntp_control_message,
	ntp_private_message,
	gre_message,
	gre_pptp_message,
	esp,
	unrecognised_ip_protocol,
	wlan,
	tls_unknown,
 	tls_client_hello,
 	tls_server_hello,
  	tls_certificates,
  	tls_server_key_exchange,
  	tls_server_hello_done,
  	tls_handshake_generic,
  	tls_certificate_request,
  	tls_client_key_exchange,
  	tls_certificate_verify,
  	tls_change_cipher_spec,
  	tls_handshake_finished,
  	tls_handshake_complete,
  	tls_application_data

    };
};

class basic_args: public qargs {

public:
    basic_args(const cybermon::context_ptr cp, const timeval& time) :
	cptr(cp), time(time) {
    }
    cybermon::context_ptr cptr;
    timeval time;
};

class trigger_up_args: public qargs {

public:
    trigger_up_args(const std::string& liid, const std::string& a,
		    const timeval& time
	) :
	trupliid(liid), trupaddr(a), time(time) {
    }
    std::string trupliid;
    const std::string trupaddr;
    timeval time;
};

class trigger_down_args: public qargs {

public:
    trigger_down_args(const std::string& liid, const timeval& time) :
	trdownliid(liid), time(time) {
    }
    std::string trdownliid;
    timeval time;
};

class unrecognised_stream_args: public qargs {

public:
    unrecognised_stream_args(const cybermon::context_ptr cp,
			     cybermon::pdu_iter s, cybermon::pdu_iter e,
			     const timeval& time, int64_t posn) :
        cptr(cp), time(time), position(posn) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
    int64_t position;
};

class unrecognised_datagram_args: public qargs {

public:
    unrecognised_datagram_args(const cybermon::context_ptr cp,
			       cybermon::pdu_iter s, cybermon::pdu_iter e,
			       const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class icmp_args: public qargs {

public:
    icmp_args(const cybermon::context_ptr cp, unsigned int type,
	      unsigned int code,
	      cybermon::pdu_iter s, cybermon::pdu_iter e,
	      const timeval& time) :
	cptr(cp), icmptype(type), icmpcode(code), time(time) {
	icmpdata.resize(e - s);
	std::copy(s, e, icmpdata.begin());
    }
    cybermon::context_ptr cptr;
    unsigned int icmptype;
    unsigned int icmpcode;
    cybermon::pdu icmpdata;
    timeval time;
};

class imap_args: public qargs {

public:
    imap_args(const cybermon::context_ptr cp,
	      cybermon::pdu_iter s, cybermon::pdu_iter e,
	      const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class imap_ssl_args: public qargs {

public:
    imap_ssl_args(const cybermon::context_ptr cp,
		  cybermon::pdu_iter s, cybermon::pdu_iter e,
		  const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class pop3_args: public qargs {

public:
    pop3_args(const cybermon::context_ptr cp,
	      cybermon::pdu_iter s, cybermon::pdu_iter e,
	      const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class pop3_ssl_args: public qargs {

public:
    pop3_ssl_args(const cybermon::context_ptr cp,
		  cybermon::pdu_iter s, cybermon::pdu_iter e,
		  const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class rtp_args: public qargs {

public:
    rtp_args(const cybermon::context_ptr cp,
	     cybermon::pdu_iter s, cybermon::pdu_iter e,
	     const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class rtp_ssl_args: public qargs {

public:
    rtp_ssl_args(const cybermon::context_ptr cp,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class smtp_auth_args: public qargs {

public:
    smtp_auth_args(const cybermon::context_ptr cp,
		   cybermon::pdu_iter s, cybermon::pdu_iter e,
		   const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;

};

class sip_ssl_args: public qargs {

public:
    sip_ssl_args(const cybermon::context_ptr cp,
		 cybermon::pdu_iter s, cybermon::pdu_iter e,
		 const timeval& time) :
	cptr(cp), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    cybermon::pdu pdu;
    timeval time;
};

class sip_request_args: public qargs {

public:
    sip_request_args(const cybermon::context_ptr cp, const std::string& method,
		     const std::string& from, const std::string& to,
		     cybermon::pdu_iter s, cybermon::pdu_iter e,
		     const timeval& time) :
	cptr(cp), sipmethod(method), sipfrom(from), sipto(to), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    const std::string sipmethod;
    const std::string sipfrom;
    const std::string sipto;
    cybermon::pdu pdu;
    timeval time;
};

class sip_response_args: public qargs {

public:
    sip_response_args(const cybermon::context_ptr cp, unsigned int code,
		      const std::string& status, const std::string& from,
		      const std::string& to,
		      cybermon::pdu_iter s, cybermon::pdu_iter e,
		      const timeval& time) :
	cptr(cp), sipcode(code), sipstatus(status), sipfrom(from), sipto(
	    to), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    unsigned int sipcode;
    const std::string sipstatus;
    const std::string sipfrom;
    const std::string sipto;
    cybermon::pdu pdu;
    timeval time;
};

class http_request_args: public qargs {

public:
    http_request_args(const cybermon::context_ptr cp, const std::string& method,
		      const std::string& url,
		      const cybermon::event::http_hdr_t& hdr,
		      cybermon::pdu_iter s, cybermon::pdu_iter e,
		      const timeval& time) :
	cptr(cp), httpmethod(method), httpurl(url), httphdr(hdr),
	time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    const std::string httpmethod;
    const std::string httpurl;
  cybermon::event::http_hdr_t httphdr;
    cybermon::pdu pdu;
    timeval time;
};

class http_response_args: public qargs {

public:
    http_response_args(const cybermon::context_ptr cp, unsigned int code,
		       const std::string& status,
		       const cybermon::event::http_hdr_t& hdr,
		       const std::string& url,
		       cybermon::pdu_iter s, cybermon::pdu_iter e,
		       const timeval& time) :
	cptr(cp), httpcode(code), httpstatus(status), httphdr(hdr), httpurl(
	    url), time(time) {
	pdu.resize(e - s);
	std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    unsigned int httpcode;
    const std::string httpstatus;
    cybermon::event::http_hdr_t httphdr;
    const std::string httpurl;
    cybermon::pdu pdu;
    timeval time;
};

class smtp_command_args: public qargs {

public:
    smtp_command_args(const cybermon::context_ptr cp,
		      const std::string& command, const timeval& time) :
	cptr(cp), smtpcommand(command), time(time) {
    }
    cybermon::context_ptr cptr;
    const std::string smtpcommand;
    timeval time;
};

class smtp_response_args: public qargs {

public:
    smtp_response_args(const cybermon::context_ptr cp, int status,
		       const std::list<std::string>& text,
		       const timeval& time) :
	cptr(cp), smtpstatus(status), smtptext(text), time(time) {
    }
    cybermon::context_ptr cptr;
    int smtpstatus;
    const std::list<std::string> smtptext;
    timeval time;
};

class smtp_data_args: public qargs {

public:
    smtp_data_args(const cybermon::context_ptr cp, const std::string& from,
		   const std::list<std::string>& to,
		   std::vector<unsigned char>::const_iterator s,
		   std::vector<unsigned char>::const_iterator e, const timeval& time) :
	cptr(cp), smtpfrom(from), smtpto(to), smtps(s), smtpe(e), time(time) {
    }
    cybermon::context_ptr cptr;
    const std::string smtpfrom;
    const std::list<std::string> smtpto;
    std::vector<unsigned char>::const_iterator smtps;
    std::vector<unsigned char>::const_iterator smtpe;
    timeval time;
};

class ftp_command_args: public qargs {

public:
    ftp_command_args(const cybermon::context_ptr cp, const std::string& command, const timeval& time) :
	cptr(cp), ftpcommand(command), time(time) {
    }
    cybermon::context_ptr cptr;
    const std::string ftpcommand;
    timeval time;
};

class ftp_response_args: public qargs {

public:
    ftp_response_args(const cybermon::context_ptr cp, int status,
		      const std::list<std::string>& responses,
		      const timeval& time) :
	cptr(cp), ftpstatus(status), ftpresponses(responses), time(time) {
    }
    cybermon::context_ptr cptr;
    int ftpstatus;
    const std::list<std::string> ftpresponses;
    timeval time;
};

class dns_message_args: public qargs {

public:
    dns_message_args(const cybermon::context_ptr cp,
		     const cybermon::dns_header hdr,
		     const std::list<cybermon::dns_query> queries,
		     const std::list<cybermon::dns_rr> answers,
		     const std::list<cybermon::dns_rr> authorities,
		     const std::list<cybermon::dns_rr> additional,
		     const timeval& time) :
	cptr(cp), dnshdr(hdr), dnsqueries(queries), dnsanswers(answers),
	dnsauthorities(authorities), dnsadditional(additional), time(time) {
    }
    cybermon::context_ptr cptr;
    cybermon::dns_header dnshdr;
    std::list<cybermon::dns_query> dnsqueries;
    std::list<cybermon::dns_rr> dnsanswers;
    std::list<cybermon::dns_rr> dnsauthorities;
    std::list<cybermon::dns_rr> dnsadditional;
    timeval time;
};

class ntp_timestamp_message_args: public qargs {

public:
    ntp_timestamp_message_args(const cybermon::context_ptr cp,
			       const cybermon::ntp_timestamp& ts,
			       const timeval& time) :
	cptr(cp), ntpts(ts), time(time) {
    }
    cybermon::context_ptr cptr;
    const cybermon::ntp_timestamp ntpts;
    timeval time;
};

class ntp_control_message_args: public qargs {

public:
    ntp_control_message_args(const cybermon::context_ptr cp,
			     const cybermon::ntp_control& ctrl,
			     const timeval& time) :
	cptr(cp), ntpctrl(ctrl), time(time) {
    }
    cybermon::context_ptr cptr;
    const cybermon::ntp_control ntpctrl;
    timeval time;
};

class ntp_private_message_args: public qargs {
public:
    ntp_private_message_args(const cybermon::context_ptr cp,
			     const cybermon::ntp_private& priv,
			     const timeval& time) :
	cptr(cp), ntppriv(priv), time(time) {
    }
    cybermon::context_ptr cptr;
    const cybermon::ntp_private ntppriv;
    timeval time;
};

class gre_args: public qargs {

public:
    gre_args(const cybermon::context_ptr cp, const std::string& nextProto,
		   const uint32_t key, const uint32_t seqNo,
       cybermon::pdu_iter s, cybermon::pdu_iter e,
       const timeval& time) :
	cptr(cp), nextProto(nextProto), key(key), sequenceNo(seqNo), time(time) {
    pdu.resize(e - s);
    std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    const std::string nextProto;
    const uint32_t key;
    const uint32_t sequenceNo;
    cybermon::pdu pdu;
    timeval time;
};

class gre_pptp_args: public qargs {

public:
    gre_pptp_args(const cybermon::context_ptr cp, const std::string& nextProto,
		   const uint16_t len, const uint16_t c_id,
       const uint32_t seqNo, const uint32_t ackNo,
       cybermon::pdu_iter s, cybermon::pdu_iter e,
       const timeval& time) :
	cptr(cp), nextProto(nextProto), payload_length(len), call_id(c_id), sequenceNo(seqNo), ackNo(ackNo), time(time) {
    pdu.resize(e - s);
    std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    const std::string nextProto;
    const uint16_t payload_length;
    const uint16_t call_id;
    const uint32_t sequenceNo;
    const uint32_t ackNo;
    cybermon::pdu pdu;
    timeval time;
};

class esp_args: public qargs {

public:
    esp_args(const cybermon::context_ptr cp,
       const uint32_t spi, const uint32_t seq, const uint32_t len,
       cybermon::pdu_iter s, cybermon::pdu_iter e,
       const timeval& time) :
	cptr(cp), spi(spi), sequence(seq), length(len), time(time) {
    pdu.resize(e - s);
    std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    const uint32_t spi;
    const uint32_t sequence;
    const uint32_t length;
    cybermon::pdu pdu;
    timeval time;
};

class unknown_ip_proto_args: public qargs {

public:
    unknown_ip_proto_args(const cybermon::context_ptr cp,
       const uint8_t nxtProto, const uint32_t len,
       cybermon::pdu_iter s, cybermon::pdu_iter e,
       const timeval& time) :
	cptr(cp), nxtProto(nxtProto), length(len), time(time) {
    pdu.resize(e - s);
    std::copy(s, e, pdu.begin());
    }
    cybermon::context_ptr cptr;
    const uint8_t nxtProto;
    const uint32_t length;
    cybermon::pdu pdu;
    timeval time;
};

class wlan_args: public qargs {

public:
    wlan_args(const cybermon::context_ptr cp,
       const uint8_t version, const uint8_t type, const uint8_t subtype,
       const uint8_t flags, const bool is_protected, const uint16_t duration,
       const std::string& filt_addr, const uint8_t frag_num, const uint16_t seq_num,
       const timeval& time) :
	cptr(cp), version(version), type(type), subtype(subtype), flags(flags),
  is_protected(is_protected), duration(duration), filt_addr(filt_addr), frag_num(frag_num),
  seq_num(seq_num), time(time) {
    }
    cybermon::context_ptr cptr;
    const uint8_t version;
    const uint8_t type;
    const uint8_t subtype;
    const uint8_t flags;
    const bool is_protected;
    const uint16_t duration;
    const std::string filt_addr;
    const uint8_t frag_num;
    const uint16_t seq_num;
    timeval time;
};

class tls_unknown_args: public qargs {

public:
    tls_unknown_args(const cybermon::context_ptr cp,
       const std::string& version, const uint8_t contentType,
       const uint16_t length, const timeval& time) :
	cptr(cp), version(version), contentType(contentType), length(length), time(time) {
    }
    cybermon::context_ptr cptr;
    const std::string version;
    const uint8_t contentType;
    const uint16_t length;
    cybermon::pdu pdu;
    timeval time;
};

class tls_client_hello_args: public qargs {

public:
    tls_client_hello_args(const cybermon::context_ptr cp,
      const cybermon::tls_handshake_protocol::client_hello_data& data, const timeval& time)
      : cptr(cp), data(data), time(time) // copy of data is ok because copy constructor is a deep copy
    {
    }
    cybermon::context_ptr cptr;
    const cybermon::tls_handshake_protocol::client_hello_data data;
    timeval time;
};

class tls_server_hello_args: public qargs {

public:
    tls_server_hello_args(const cybermon::context_ptr cp,
      const cybermon::tls_handshake_protocol::server_hello_data& data, const timeval& time)
      : cptr(cp), data(data), time(time) // copy of data is ok because copy constructor is a deep copy
    {
    }
    cybermon::context_ptr cptr;
    const cybermon::tls_handshake_protocol::server_hello_data data;
    timeval time;
};

class tls_certificates_args: public qargs {

public:
    tls_certificates_args(const cybermon::context_ptr cp,
      const std::vector<std::vector<uint8_t>>& certsArg, const timeval& time)
      : cptr(cp), time(time) // copy of data is ok because copy constructor is a deep copy
    {
      certs.reserve(certsArg.size());
      certs.insert(certs.end(), certsArg.begin(), certsArg.end());
    }
    cybermon::context_ptr cptr;
    std::vector<std::vector<uint8_t>> certs;
    timeval time;
};

class tls_server_key_exchange_args: public qargs {

public:
    tls_server_key_exchange_args(const cybermon::context_ptr cp,
      const cybermon::tls_handshake_protocol::key_exchange_data& data, const timeval& time)
      : cptr(cp), data(data), time(time) // copy of data is ok because copy constructor is a deep copy
    {
    }
    cybermon::context_ptr cptr;
    const cybermon::tls_handshake_protocol::key_exchange_data data;
    timeval time;
};

class tls_handshake_generic_args: public qargs {

public:
    tls_handshake_generic_args(const cybermon::context_ptr cp,
      const uint8_t type, const uint32_t len, const timeval& time)
      : cptr(cp), type(type), len(len), time(time)
    {
    }
    cybermon::context_ptr cptr;
    const uint8_t type;
    const uint32_t len;
    timeval time;
};

class tls_certificate_request_args: public qargs {

public:
    tls_certificate_request_args(const cybermon::context_ptr cp,
      const cybermon::tls_handshake_protocol::certificate_request_data& data, const timeval& time)
      : cptr(cp), data(data), time(time) // copy of data is ok because copy constructor is a deep copy
    {
    }
    cybermon::context_ptr cptr;
    const cybermon::tls_handshake_protocol::certificate_request_data data;
    timeval time;
};

class tls_client_key_exchange_args: public qargs {

public:
    tls_client_key_exchange_args(const cybermon::context_ptr cp,
      const std::vector<uint8_t>& key, const timeval& time)
      : cptr(cp), key(key), time(time)
    {
    }
    cybermon::context_ptr cptr;
    const std::vector<uint8_t> key;
    timeval time;
};

class tls_certificate_verify_args: public qargs {

public:
    tls_certificate_verify_args(const cybermon::context_ptr cp,
      const uint8_t sigHashAlgo, const uint8_t sigAlgo,
      const std::string& sig, const timeval& time)
      : cptr(cp), sigHashAlgo(sigHashAlgo), sigAlgo(sigAlgo), sig(sig), time(time)
    {
    }
    cybermon::context_ptr cptr;
    const uint8_t sigHashAlgo;
    const uint8_t sigAlgo;
    const std::string sig;
    timeval time;
};

class tls_change_cipher_spec_args: public qargs {

public:
    tls_change_cipher_spec_args(const cybermon::context_ptr cp,
      const uint8_t val, const timeval& time)
      : cptr(cp), val(val), time(time)
    {
    }
    cybermon::context_ptr cptr;
    const uint8_t val;
    timeval time;
};

class tls_handshake_finished_args: public qargs {

public:
    tls_handshake_finished_args(const cybermon::context_ptr cp,
      const std::vector<uint8_t>& msg, const timeval& time)
      : cptr(cp), msg(msg), time(time)
    {
    }
    cybermon::context_ptr cptr;
    const std::vector<uint8_t> msg;
    timeval time;
};

class tls_application_data_args: public qargs {

public:
    tls_application_data_args(const cybermon::context_ptr cp, const std::string& ver,
      const std::vector<uint8_t>& data, const timeval& time)
      : cptr(cp), version(ver), data(data), time(time)
    {
    }
    cybermon::context_ptr cptr;
    const std::string version;
    const std::vector<uint8_t> data;
    timeval time;
};

/*q_entry class acting as a medium to store args and add in to queue by cybermon_qwriter
 * and cybermon_qreader pick up it from queue to process by calling
 * cybermon lua bridge
 */
class q_entry {

public:
    //Constructor
    q_entry(qargs::call_type call, qargs* args) :
	calltype(call), queueargs(args) {
    }

    //Constructor
    q_entry(const q_entry &obj) {
	queueargs = obj.queueargs;
	calltype = obj.calltype;
    }

    q_entry& operator=(const q_entry &obj) {
	if (this != &obj) {
	    queueargs = obj.queueargs;
	    calltype = obj.calltype;
	}
	return *this;
    }

    //Destructor
    virtual ~q_entry() {
    }

    qargs::call_type calltype;
    qargs* queueargs;

};

#endif /* CYBERMON_QARGS_H_ */
