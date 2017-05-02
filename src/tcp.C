
#include <cybermon/tcp.h>

#include <boost/array.hpp>
#include <boost/regex.hpp>
#include <set>

#include <cybermon/manager.h>
#include <cybermon/pdu.h>
#include <cybermon/context.h>
#include <cybermon/http.h>
#include <cybermon/unrecognised.h>
#include <cybermon/forgery.h>
#include <cybermon/ftp.h>
#include <cybermon/imap.h>
#include <cybermon/imap_ssl.h>
#include <cybermon/pop3.h>
#include <cybermon/pop3_ssl.h>
#include <cybermon/smtp.h>
#include <cybermon/smtp_auth.h>


using namespace cybermon;


const unsigned int tcp_context::ident_buffer_max = 20;
const unsigned int tcp_context::max_segments = 100;

void tcp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    if ((e - s) < 20)
	throw exception("Header too small for TCP header");

    // TCP ports
    address src, dest;
    src.set(s, s + 2, TRANSPORT, TCP);
    dest.set(s + 2, s + 4, TRANSPORT, TCP);

    uint32_t seq = (s[4] << 24) + (s[5] << 16) + (s[6] << 8) + s[7];
    uint32_t ack = (s[8] << 24) + (s[9] << 16) + (s[10] << 8) + s[11];
    uint16_t offset = s[12] >> 4;
    uint16_t flags = ((s[12] & 0xf) << 8) + s[13];

    unsigned int header_length = 4 * offset;
    uint32_t payload_length = (e - s) - header_length;

    // FIXME: Check checksum?

    flow_address f(src, dest);

    tcp_context::ptr fc = tcp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    fc->lock.lock();

    // Store the last ack.
    if (flags & ACK) {
	fc->ack_received = ack;
    }

    // This is for the initial setup.  Works for both directions, ISN = seq + 1
    if (flags & SYN) {
	fc->syn_observed = true;
	fc->seq_expected = seq + 1;
	fc->m_first_seq = seq;
	fc->lock.unlock();
	return;
    }

    // This works for either the step2 SYN/ACK or the step3 ACK.
    if ((flags & ACK) && !fc->connected) {
	fc->connected = true;
	mgr.connection_up(fc);
    }

    // This works for the either of the close-down packets containing a FIN.
    if ((flags & (FIN|RST)) && !fc->fin_observed) {
	fc->fin_observed = true;
	fc->set_ttl(2);
	fc->lock.unlock();
	mgr.connection_down(fc);
	return;
    }

    // Haven't ever seen SYN... ignore.
    if (fc->syn_observed == false) {
	// FIXME: Do something more useful.  Should at least event on the
	// data.
	fc->lock.unlock();
	return;
    }

    // In a connected state.
    // First deal with this PDU.  Either process it, or put it on the queue.

    if (fc->seq_expected == seq) {

	// Advance the expected sequence.
	fc->seq_expected += payload_length;

	if (payload_length > 0) {
	    fc->lock.unlock();
	    post_process(mgr, fc, s + header_length, e);
	    fc->lock.lock();
	}

	fc->m_seq = seq;
    }
    else if(payload_length && (fc->m_seq == seq))
    {
	// a retransmission
	const uint32_t expected_next_seq = seq + payload_length;
	if (fc->seq_expected == expected_next_seq)
	{
	    // simple common retransmission case
	}
	else if (fc->seq_expected < expected_next_seq)
	{
	    // a retransmission having a bigger payload.
	    // So process the extra bytes

	    // note: this calc is guarenteed to be positive
	    const uint32_t payload_subset_len =
		expected_next_seq - fc->seq_expected.value();
	    fc->lock.unlock();
	    if (s > (e - payload_subset_len))
	    {
		throw exception("TCP calculation logic error");
	    }
	    post_process(mgr, fc, e - payload_subset_len, e);
	    fc->lock.lock();
	    fc->seq_expected = expected_next_seq;
	}
	else if (fc->seq_expected > expected_next_seq)
	{
	    // FIXME: this packet may be interesting?
	    // See http://en.wikipedia.org/wiki/TCP_sequence_prediction_attack
	}
	else
	{
	    fc->lock.unlock();
	    throw exception("TCP retransmission logic error");
	}

	fc->lock.unlock();
	return;
    }
    else if (fc->seq_expected > (seq + payload_length))
    {
	fc->lock.unlock();

	if (payload_length)
	{
	    if (fc->m_seq >= seq)
	    {
		// An old seq delivered - unusual but not unexpected
	    }
	    else
	    {

	        // FIXME: We do see this?

		// Very odd to see this
		throw exception("Unexpected seq logic error");
	    }
	}
	return;

    }
    else {

	// Can't use it now.  Put it on the queue.

	// Put this segment at the back of the list.
	// FIXME: Too much copying.
	tcp_segment ts;
	ts.first = seq;
	ts.last = seq + payload_length;
	ts.segment.assign(s + header_length, e);
	fc->segments.insert(ts);

	// Check for queue filling up.
	if (fc->segments.size() > fc->max_segments) {

	    // Rectify the situation by leaping over the hole.
	    fc->seq_expected = fc->segments.begin()->first;

	    // FIXME: Should report this occurance as an event.

	}

    }

    // Now time to look at the queue, in case this new PDU has allowed queued
    // items to be used.
        
    while (1) {

	// If empty queue, bail out.
	if (fc->segments.empty())
	    break;
	
	// Study first item on queue.

	// Is it any use?
	if (fc->seq_expected >= fc->segments.begin()->first) {

	    // Is it too late for this one?
	    if (fc->seq_expected >=  fc->segments.begin()->last) {

		// It's no use now.

		// What's it doing on the queue?  Probably a dup of a packet
		// that we couldn't use straight away.

		// Get rid of it.  
		fc->segments.erase(fc->segments.begin());

		continue;

	    }

	    // At this point we know at least some of the first segment is
	    // useful.  Will want all of it in most cases.
	    
	    // Work out how much to chuck away.
	    int unwanted = 
		fc->seq_expected.distance(fc->segments.begin()->first);

	    // We already compared (>=) those two values above, this must be
	    // positive or zero.

	    fc->lock.unlock();

	    post_process(mgr, fc, 
			 fc->segments.begin()->segment.begin() + unwanted,
			 fc->segments.begin()->segment.end());

	    fc->lock.lock();

	    fc->seq_expected = fc->segments.begin()->last;

	    // Remove the used segment.
	    fc->segments.erase(fc->segments.begin());

	    continue;

	}

	// PDU at start of queue was no use.  Bail.
	
	break;

    }

    fc->lock.unlock();
    
}

void tcp::post_process(manager& mgr, tcp_context::ptr fc, 
                       pdu_iter s, pdu_iter e)
{

    static const boost::regex 
    http_request("(OPTIONS|GET|HEAD|POST|PUT|DELETE|CONNECT|TRACE)"
             " [^ ]* HTTP/1.",
             boost::regex::extended);

    static const boost::regex http_response("HTTP/1\\.");

    fc->lock.lock();

    if (!fc->svc_idented)
    {
        uint16_t src = fc->addr.src.get_uint16();
        uint16_t dest = fc->addr.dest.get_uint16();

        // Attempt to identify from the port number and
        // call the appropriate handler if there is one
        if (tcp_ports::has_port_handler(src) || tcp_ports::has_port_handler(dest))
        {
            // Unfortunately now need to repeat the check
            // to determine port number has the associated handler
            if (tcp_ports::has_port_handler(src))
            {
                fc->processor = tcp_ports::get_port_handler(src);
            }
            else
            {
                fc->processor = tcp_ports::get_port_handler(dest);
            }

            fc->svc_idented = true;

            fc->lock.unlock();

            (*fc->processor)(mgr, fc, s, e);
            return;
        }
        else
        {
            // Ident by studing the data.

            // Copy into the ident buffer.
            fc->ident_buffer.insert(fc->ident_buffer.end(), s, e);

            // If not enough to run an ident, bail out.
            if (fc->ident_buffer.size() < fc->ident_buffer_max)
            {
                fc->lock.unlock();
                return;
            }

            // Not idented, and we have enough data for an ident attempt.

            boost::match_results<std::string::const_iterator> what;
        
            if (regex_search(fc->ident_buffer, what, http_request, 
                                 boost::match_continuous))
            {
                fc->processor = &http::process_request;
                fc->svc_idented = true;
            }
            else if (regex_search(fc->ident_buffer, what, http_response,
                                    boost::match_continuous))
            {
                fc->processor = &http::process_response;
                fc->svc_idented = true;
            }
            else
            {    
                // Default.
                fc->processor = &unrecognised::process_unrecognised_stream;
                fc->svc_idented = true;
            }
        }
    
        // Good, we're idented now.

        fc->lock.unlock();

        // Just need to process what's in the buffer.

        pdu p;
        p.assign(fc->ident_buffer.begin(), fc->ident_buffer.end());

        (*fc->processor)(mgr, fc, p.begin(), p.end());
        return;
    }
    
    fc->lock.unlock();
 
    // Process the data using the defined processing function.
    (*fc->processor)(mgr, fc, s, e);
    return;
}

void tcp::checksum(pdu_iter s, pdu_iter e, uint16_t& sum)
{

    pdu_iter ptr = s;

    uint32_t tmp = sum;

    // Handle 2-bytes at a time.
    while ((e - ptr) > 1) {
	tmp += (ptr[0] << 8) + ptr[1];
	if (tmp & 0x80000000)
	    tmp = (tmp & 0xffff) + (tmp >> 16);
	ptr += 2;
    }

    // If a remaining byte, handle that.
    if ((e - ptr) != 0)
	tmp += ptr[0] << 8;

    while (tmp >> 16) {
	tmp = (tmp & 0xffff) + (tmp >> 16);
    }

    sum = tmp;

}

uint16_t tcp::calculate_ip4_cksum(pdu_iter src,  // IPv4 address
				  pdu_iter dest, // IPv4 address
				  uint16_t protocol,
				  uint16_t length,
				  pdu_iter s,    // TCP hdr + body
				  pdu_iter e)
{

    uint16_t sum = 0;

    checksum(s, e, sum);

    checksum(src, src + 4, sum);

    checksum(dest, dest + 4, sum);

    pdu tmp;
    tmp.push_back(0);
    tmp.push_back(protocol);
    tmp.push_back((length & 0xff00) >> 8);
    tmp.push_back(length & 0xff);

    checksum(tmp.begin(), tmp.begin() + 4, sum);

    return ~sum;

}
