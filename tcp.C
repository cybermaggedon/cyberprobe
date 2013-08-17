
#include <boost/regex.hpp>

#include "tcp.h"
#include "manager.h"
#include "pdu.h"
#include "context.h"
#include "http.h"

using namespace analyser;

void tcp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    if ((e - s) < 20)
	throw exception("Header too small for TCP header");

    // TCP ports
    address src, dest;
    src.assign(s, s + 2, TRANSPORT, TCP);
    dest.assign(s + 2, s + 4, TRANSPORT, TCP);

    uint32_t seq = (s[4] << 24) + (s[5] << 16) + (s[6] << 8) + s[7];
    uint16_t offset = s[12] >> 4;
    uint16_t flags = ((s[12] & 0xf) << 8) + s[13];
    uint32_t cksum = (s[16] << 8) + s[17];

    unsigned int header_length = 4 * offset;
    uint32_t payload_length = (e - s) - header_length;

    // FIXME: Check checksum?

    flow f(src, dest);

    // FIXME: Locking.
    // FIXME: Race condition on get_context once locking is fixed.

    tcp_context::ptr fc = tcp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    fc->lock.lock();

    // This is for the initial setup.  Works for both directions, ISN = seq + 1
    if (flags & SYN) {
	fc->syn_observed = true;
	fc->seq_expected = seq + 1;
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

    // Firstly, do we need it?  If it preceeds the sequence number we're
    // looking out for, it isn't needed now: Resend of something we already
    // have.
    if (fc->seq_expected > (seq + payload_length)) {

	// Going to ignore the packet because it's a resend or something like
	// that.

	// FIXME: But the packet may be interesting?
	// See http://en.wikipedia.org/wiki/TCP_sequence_prediction_attack

	fc->lock.unlock();

	return;

    }


    // First deal with this PDU.  Either process it, or put it on the queue.

    if (fc->seq_expected == seq) {

	// Advance the expected sequence.
	fc->seq_expected += payload_length;

	if (payload_length > 0) {
	    fc->lock.unlock();
	    post_process(mgr, fc, s + header_length, e);
	    fc->lock.lock();
	}
	    

    } else {

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

    // All done?  Leave.
    if (fc->segments.empty()) {
	fc->lock.unlock();
	return;
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

		// What's it doing on the queue?

		// Get rid of it, and moan.
		fc->segments.erase(fc->segments.begin());

		fc->lock.unlock();

		throw std::runtime_error("TCP queue management is broken");

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

    if (!fc->svc_idented) {

#ifdef OH_SOD_IT

	// We could copy the whole buffer?
	int to_copy = e - s;

	// But not if that would overflow.
	if ((fc->ident_buffer.size() + (e - s)) > fc->ident_buffer_max) {
	    
	    // In that case, copy less.
	    to_copy = fc->ident_buffer_max - fc->ident_buffer.size();

	}

	fc->ident_buffer.append(s, s + to_copy);

#endif

	fc->ident_buffer.append(s, e);

	// If not enough to run an ident, bail out.
	if (fc->ident_buffer.size() < fc->ident_buffer_max) {
	    fc->lock.unlock();
	    return;
	}

	// Not idented, and we have enough data for an ident attempt.

	boost::match_results<std::string::const_iterator> what;

	if (regex_search(fc->ident_buffer, what, http_request,
			 boost::match_continuous)) {
	    
	    fc->processor = &http::process_request;
	    fc->svc_idented = true;

	} else 	if (regex_search(fc->ident_buffer, what, http_response,
				 boost::match_continuous)) {

	    fc->processor = &http::process_response;
	    fc->svc_idented = true;

	} else {
	
	    // Default.
	    fc->processor = 0;
	    fc->svc_idented = true;
	    
	}
	
	// Good, we're idented now.

	fc->lock.unlock();

	// Just need to process what's in the buffer.
	tcp::post_process(mgr, fc, fc->ident_buffer.begin(),
			  fc->ident_buffer.end());
	return;
	

    }

    // Process the data using the processing function if defined.  Otherwise
    // use connection_data.
    if (fc->processor)
	(*fc->processor)(mgr, fc, s, e);
    else
	mgr.connection_data(fc, s, e);

    return;


}


