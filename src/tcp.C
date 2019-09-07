
#include <cyberprobe/protocol/tcp.h>

#include <regex>
#include <set>

#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>
#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/http.h>
#include <cyberprobe/protocol/unrecognised.h>
#include <cyberprobe/protocol/forgery.h>
#include <cyberprobe/protocol/ftp.h>
#include <cyberprobe/protocol/imap.h>
#include <cyberprobe/protocol/imap_ssl.h>
#include <cyberprobe/protocol/pop3.h>
#include <cyberprobe/protocol/pop3_ssl.h>
#include <cyberprobe/protocol/smtp.h>
#include <cyberprobe/protocol/smtp_auth.h>
#include <cyberprobe/event/event_implementations.h>


using namespace cyberprobe::protocol;


const unsigned int tcp_context::ident_buffer_max = 20;
const unsigned int tcp_context::max_segments = 100;

void tcp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

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

#ifdef DEBUG
    std::cerr << "Flags:" << std::endl
              << (flags & SYN ? " SYN" : "")
              << (flags & FIN ? " FIN" : "")
              << (flags & ACK ? " ACK" : "")
              << (flags & RST ? " RST" : "")
              << " seq=" << seq
              << " ack=" << ack
              << std::endl;
#endif

    flow_address f(src, dest, sl.direc);

    tcp_context::ptr fc = tcp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    std::unique_lock<std::mutex> lock(fc->mutex);

    // Store the last ack.
    if (flags & ACK) {
	fc->ack_received = ack;
    }

    // This is for the initial setup.  Works for both directions, ISN = seq + 1
    if (flags & SYN) {
	fc->syn_observed = true;
	fc->seq_expected = seq + 1;
	return;
    }

    // This works for either the step2 SYN/ACK or the step3 ACK.
    if ((flags & ACK) && !fc->connected) {
	fc->connected = true;
	auto ev =
	    std::make_shared<event::connection_up>(fc, sl.time);
	mgr.handle(ev);
    }

    // This works for the either of the close-down packets containing a FIN.
    if ((flags & (FIN|RST)) && !fc->fin_observed) {
	fc->fin_observed = true;
	fc->set_ttl(2);
	auto ev =
	    std::make_shared<event::connection_down>(fc, sl.time);
	mgr.handle(ev);
	return;
    }

    // Haven't ever seen SYN... ignore.  Could be a SYN flood, could be
    // packets with weird ordering.  Could be a port scan.
    if (fc->syn_observed == false) {
	// FIXME: Do something more useful.  Should at least event on the
	// data.
	return;
    }

    // In a connected state.
    // First deal with this PDU.  Either process it, or put it in the segment
    // queue.

    // Zero length payload, we can just move on.  Done all the flag handling.
    if (payload_length == 0) {
	return;
    }

    // The algorithm here is two phases.  The first phase looks at the
    // input PDU:
    // - Can we use it straight away?  If so, just process it.
    // - If not, put it on the segments list.
    // Phase two looks at the segments list and either uses PDU which we can
    // use, or discard ones which are superfluous.

    if (fc->seq_expected == seq) {

	// This is the case where it's the next PDU we were expected.
	// Easy case, just process the data.

	// Advance the expected sequence.
	fc->seq_expected += payload_length;

	// If there's data, process the data.
	if (payload_length > 0) {
	    lock.unlock();
	    post_process(mgr, fc, sl.skip(header_length));
	    lock.lock();
	}

    } else {

	// Second case, it's not the expected packet.  Plan is to put the
	// PDU in the segment queue, and process what's in the queue.
	
	// Can't use it now.  Put it on the segments queue.

	// Put this segment at the back of the list.
	// FIXME: Too much copying.
	tcp_segment ts;
	ts.first = seq;
	ts.last = seq + payload_length;
	ts.segment.assign(s + header_length, e);
	fc->segments.insert(ts);

	// Check for queue filling up.
	if (fc->segments.size() > fc->max_segments) {

	    // Rectify the situation by leaping over the hole to the first
	    // segment in the queue.
	    fc->seq_expected = fc->segments.begin()->first;

	    // FIXME: Should report this occurance as an event.

	}

    }

    // Now time to look at the segment set, in case this new PDU has allowed
    // queued items to be used.
        
    while (1) {

	// If empty queue, bail out.
	if (fc->segments.empty())
	    break;
	
	// Study first item on queue.

	// Is it any use? i.e. its sequence num is less than what we're looking
	// for.
	if (fc->seq_expected >= fc->segments.begin()->first) {

	    // Does it totally precede the sequence number we want?
	    if (fc->seq_expected >=  fc->segments.begin()->last) {

		// It's no use now.

		// What's it doing on the queue?  Probably a dup of a packet
		// that we couldn't use straight away.

		// Discard, and loop round.
		fc->segments.erase(fc->segments.begin());

		continue;

	    }

	    // At this point we know at least some of the first segment is
	    // useful.  Will want all of it in most cases.  If any of it is
	    // not wanted, it will at the start of the segment.
	    
	    // Work out how much to chuck away.
	    int unwanted = 
		fc->seq_expected.distance(fc->segments.begin()->first);

	    // We already compared (>=) those two values above, this must be
	    // positive or zero.

	    lock.unlock();

	    pdu_slice sl2(fc->segments.begin()->segment.begin() + unwanted,
                          fc->segments.begin()->segment.end(),
                          sl.time, sl.direc);

	    post_process(mgr, fc, sl2);

	    lock.lock();

	    fc->seq_expected = fc->segments.begin()->last;

	    // Remove the used segment.
	    fc->segments.erase(fc->segments.begin());

	    // Loop round, see if the next is any use.
	    continue;

	}

	// PDU at start of queue is no use yet, stop processing.
	
	break;

    }
    
}

void tcp::post_process(manager& mgr, tcp_context::ptr fc, 
                       const pdu_slice& sl)
{

    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

    static const std::regex 
        http_request("(OPTIONS|GET|HEAD|POST|PUT|DELETE|CONNECT|TRACE)"
                     " [^ ]* HTTP/1.",
                     std::regex::extended);

    static const std::regex http_response("HTTP/1\\.");

    std::unique_lock<std::mutex> lock(fc->mutex);

    if (!fc->svc_idented) {

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
		    } else {
			fc->processor = tcp_ports::get_port_handler(dest);
		    }

		fc->svc_idented = true;

		lock.unlock();

		(*fc->processor)(mgr, fc, sl);
		return;
	    }
	else
	    {
		// Ident by studing the data.

		// Copy into the ident buffer.
		fc->ident_buffer.insert(fc->ident_buffer.end(), s, e);

		// If not enough to run an ident, bail out.
		if (fc->ident_buffer.size() < fc->ident_buffer_max) {
			return;
		    }

		// Not idented, and we have enough data for an ident attempt.

		std::match_results<std::string::const_iterator> what;
        
		if (regex_search(fc->ident_buffer, what, http_request, 
				 std::regex_constants::match_continuous)) {
		    fc->processor = &http::process_request;
		    fc->svc_idented = true;
		} else
		    if (regex_search(fc->ident_buffer, what, http_response,
				     std::regex_constants::match_continuous)) {
			fc->processor = &http::process_response;
			fc->svc_idented = true;
		    } else {    
			// Default.
			fc->processor = &unrecognised::process_unrecognised_stream;
			fc->svc_idented = true;
		    }
	    }
    
	// Good, we're idented now.

	// Just need to process what's in the buffer.

	pdu p;
	p.assign(fc->ident_buffer.begin(), fc->ident_buffer.end());

	lock.unlock();

	(*fc->processor)(mgr, fc, pdu_slice(p.begin(), p.end(), sl.time,
					    sl.direc));
	return;
    }

    lock.unlock();
    
    // Process the data using the defined processing function.
    (*fc->processor)(mgr, fc, sl);
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
