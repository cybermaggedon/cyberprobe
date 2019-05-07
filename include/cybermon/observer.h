
#ifndef CYBERMON_OBSERVER_H
#define CYBERMON_OBSERVER_H

#include <cybermon/context.h>
#include <cybermon/dns_protocol.h>
#include <cybermon/ntp_protocol.h>
#include <cybermon/tls_handshake_protocol.h>

#include <vector>

namespace cybermon {

    // Observer interface.  The observer interface is called when various
    // reportable events occur.
    class observer {
    public:
	
	// Connection-orientated.
	virtual void connection_up(const context_ptr cp,
				   const timeval& tv) = 0;
	virtual void connection_down(const context_ptr cp,
				     const timeval& tv) = 0;

	virtual void unrecognised_stream(const context_ptr cp,
					 pdu_iter s, pdu_iter e,
					 const timeval& tv,
                                         int64_t posn) = 0;

	// Connection-less
	virtual void unrecognised_datagram(const context_ptr cp,
					   pdu_iter s, pdu_iter e,
					   const timeval& tv) = 0;

	virtual void icmp(const context_ptr cp,
			  unsigned int type,
			  unsigned int code,
			  pdu_iter s,
			  pdu_iter e,
			  const timeval& tv) = 0;

	virtual void imap(const context_ptr cp,
			  pdu_iter s,
			  pdu_iter e,
			  const timeval& tv) = 0;
	
	virtual void imap_ssl(const context_ptr cp,
			      pdu_iter s,
			      pdu_iter e,
			      const timeval& tv) = 0;

	virtual void pop3(const context_ptr cp,
			  pdu_iter s,
			  pdu_iter e,
			  const timeval& tv) = 0;

	virtual void pop3_ssl(const context_ptr cp,
			      pdu_iter s,
			      pdu_iter e,
			      const timeval& tv) = 0;

	virtual void rtp(const context_ptr cp,
			 pdu_iter s,
			 pdu_iter e,
			 const timeval& tv) = 0;

	virtual void rtp_ssl(const context_ptr cp,
			     pdu_iter s,
			     pdu_iter e,
			     const timeval& tv) = 0;

	virtual void sip_request(const context_ptr cp,
				 const std::string& method,
				 const std::string& from,
				 const std::string& to,
				 pdu_iter s,
				 pdu_iter e,
				 const timeval& tv) = 0;

	virtual void sip_response(const context_ptr cp,
				  unsigned int code,
				  const std::string& status,
				  const std::string& from,
				  const std::string& to,
				  pdu_iter s,
				  pdu_iter e,
				  const timeval& tv) = 0;
	
	virtual void sip_ssl(const context_ptr cp,
			     pdu_iter s,
			     pdu_iter e,
			     const timeval& tv) = 0;

	virtual void smtp_auth(const context_ptr cp,
			       pdu_iter s,
			       pdu_iter e,
			       const timeval& tv) = 0;

	typedef
	    std::map<std::string, std::pair<std::string,std::string> > 
	    http_hdr_t;
    
	// HTTP
	virtual void http_request(const context_ptr cp,
				  const std::string& method,
				  const std::string& url,
				  const observer::http_hdr_t& hdr,
				  pdu_iter body_start,
				  pdu_iter body_end,
				  const timeval& tv) = 0;

	virtual void http_response(const context_ptr cp,
				   unsigned int code,
				   const std::string& status,
				   const http_hdr_t& hdr,
				   // URL of object, or "" if not known.
				   const std::string& url,
				   pdu_iter body_start,
				   pdu_iter body_end,
				   const timeval& tv) = 0;


	virtual void trigger_up(const std::string& liid,
				const tcpip::address& trigger_address,
				const timeval& tv) = 0;
	virtual void trigger_down(const std::string& liid,
				  const timeval& tv) = 0;

	// SMTP
	virtual void smtp_command(const context_ptr cp,
				  const std::string& command,
				  const timeval& tv) = 0;

	virtual void smtp_response(const context_ptr cp,
				   int status,
				   const std::list<std::string>& text,
				   const timeval& tv) = 0;

	virtual void smtp_data(const context_ptr cp,
			       const std::string& from,
			       const std::list<std::string>& to,
			       pdu_iter s,
			       pdu_iter e,
			       const timeval& tv) = 0;

	// FTP
	virtual void ftp_command(const context_ptr cp,
				 const std::string& command,
				 const timeval& tv) = 0;

	virtual void ftp_response(const context_ptr cp,
				  int status,
				  const std::list<std::string>& text,
				  const timeval& tv) = 0;

	// DNS
	virtual void dns_message(const context_ptr cp,
				 const dns_header hdr,
				 const std::list<dns_query> queries,
				 const std::list<dns_rr> answers,
				 const std::list<dns_rr> authorities,
				 const std::list<dns_rr> additional,
				 const timeval& tv) = 0;

	// NTP
	virtual void ntp_timestamp_message(const context_ptr cp,
					   const ntp_timestamp& ts,
					   const timeval& tv) = 0;
			                   
	virtual void ntp_control_message(const context_ptr cp,
					 const ntp_control& ctrl,
					 const timeval& tv) = 0;
			                         
	virtual void ntp_private_message(const context_ptr cp,
				     const ntp_private& priv,
				     const timeval& tv) = 0;
 
	virtual void gre(const context_ptr cp,
				     const std::string& nxt_proto,
 				     const uint32_t key,
 				     const uint32_t seq,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv) = 0;

	virtual void gre_pptp(const context_ptr cp,
				     const std::string& nxt_proto,
 				     const uint16_t payload_length,
 				     const uint16_t call_id,
             const uint32_t sequenceNo,
             const uint32_t ackNo,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv) = 0;

	virtual void esp(const context_ptr cp,
             const uint32_t spi,
             const uint32_t seq,
             const uint32_t len,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv) = 0;

	virtual void unrecognised_ip_protocol(const context_ptr cp,
             const uint8_t nxtProto,
             const uint32_t len,
 				     pdu_iter start,
 				     pdu_iter end,
 				     const timeval& tv) = 0;

	virtual void wlan(const context_ptr cp,
 				     const uint8_t version,
 				     const uint8_t type,
 				     const uint8_t subtype,
 				     const uint8_t flags,
 				     const bool is_protected,
 				     const uint16_t duration,
 				     const std::string& filt_addr,
 				     const uint8_t frag_num,
 				     const uint16_t seq_num,
 				     const timeval& tv) = 0;

	virtual void tls(const context_ptr cp,
 				     const std::string& version,
 				     const uint8_t contentType,
 				     const uint16_t length,
 				     const timeval& tv) = 0;

	virtual void tls_client_hello(const context_ptr cp,
  				     const tls_handshake_protocol::client_hello_data& data,
 				     const timeval& tv) = 0;

	virtual void tls_server_hello(const context_ptr cp,
   				     const tls_handshake_protocol::server_hello_data& data,
 				     const timeval& tv) = 0;

	virtual void tls_certificates(const context_ptr cp,
    				     const std::vector<std::vector<uint8_t>>& certs,
 				     const timeval& tv) = 0;

    };

};

#endif
