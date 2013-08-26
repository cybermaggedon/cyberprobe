
#include "context.h"
#include "dns_protocol.h"

namespace cybermon {

    class forgery {

    public:

	static void forge_dns_response(context_ptr, 
				       const dns_header& hdr,
				       const std::list<dns_query>& queries,
				       const std::list<dns_rr>& answers,
				       const std::list<dns_rr>& authorities,
				       const std::list<dns_rr>& additional);

	static void forge_tcp_reset(context_ptr);

	static void forge_tcp_data(context_ptr, pdu_iter, pdu_iter);

	static void encode_dns_header(std::back_insert_iterator<pdu>,
				      const dns_header&);

	static void encode_dns_queries(std::back_insert_iterator<pdu>,
				       const std::list<dns_query>&);

	static void encode_dns_rr(std::back_insert_iterator<pdu>,
				  const std::list<dns_rr>&);

	static void encode_dns_name(std::back_insert_iterator<pdu>,
				    const std::string&);

	static void encode_ip_udp_header(pdu& p,
					 address& src, uint16_t sport,
					 address& dest, uint16_t dport,
					 const pdu& payload);

	static void encode_ip_tcp_header(pdu& p,
					 address& src, uint16_t sport,
					 address& dest, uint16_t dport,
					 uint32_t seq, uint32_t ack,
					 int flags,
					 const pdu& payload);

    };

};

