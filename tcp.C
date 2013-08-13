
#include "tcp.h"
#include "analyser.h"

using namespace analyser;

void tcp::process(engine& eng, context_ptr c, 
		  pdu_iter s, pdu_iter e)
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

    context_ptr fc = c->get_context(f);

    if (fc.get() == 0) {
	fc = context_ptr(new tcp_context(f, c));
	c->add_child(f, fc);
    }

    tcp_context& tc = dynamic_cast<tcp_context&>(*fc);

    // This is for the initial setup.  Works for both directions, ISN = seq + 1
    if (flags & SYN) {

	tc.syn_observed = true;
	tc.seq_expected = seq + 1;

	// FIXME: Produce a better event.
	eng.data(fc, s + header_length, e);

	return;
    }

    // Haven't ever seen SYN... ignore.
    if (tc.syn_observed == false) {

	// FIXME: Do something more useful.  Should at least event on the
	// data.
	return;
    }

    // In a connected state.

    // Firstly, do we need it?  If it preceeds the sequence number we're
    // looking out for, it isn't needed now: Resend of something we already
    // have.
    if (tc.seq_expected > (seq + payload_length)) {

	// Going to ignore the packet because it's a resend or something like
	// that.

	// FIXME: But the packet may be interesting?
	// See http://en.wikipedia.org/wiki/TCP_sequence_prediction_attack

	return;

    }


    // First deal with this PDU.  Either process it, or put it on the queue.

    if (tc.seq_expected == seq) {

	// Advance the expected sequence.
	tc.seq_expected += payload_length;

	eng.data(fc, s + header_length, e);


    } else {

	// Can't use it now.  Put it on the queue.

	// Put this segment at the back of the list.
	// FIXME: Too much copying.
	tcp_segment ts;
	ts.first = seq;
	ts.last = seq + payload_length;
	ts.segment.assign(s + header_length, e);
	tc.segments.insert(ts);

	// Check for queue filling up.
	if (tc.segments.size() > tc.max_segments) {

	    // Rectify the situation by leaping over the hole.
	    tc.seq_expected = tc.segments.begin()->first;

	    // FIXME: Should report this occurance as an event.

	}

    }

    // All done?  Leave.
    if (tc.segments.empty())
	return;

    // Now time to look at the queue, in case this new PDU has allowed queued
    // items to be used.
        
    while (1) {

	// If empty queue, bail out.
	if (tc.segments.empty())
	    break;
	
	// Study first item on queue.

	// Is it any use?
	if (tc.seq_expected >= tc.segments.begin()->first) {

	    // Is it too late for this one?
	    if (tc.seq_expected >=  tc.segments.begin()->last) {

		// What's it doing on the queue?

		// Get rid of it, and moan.
		tc.segments.erase(tc.segments.begin());
		throw std::runtime_error("TCP queue management is broken");

	    }

	    // At this point we know at least some of the first segment is
	    // useful.  Will want all of it in most cases.
	    
	    // Work out how much to chuck away.
	    int unwanted = tc.seq_expected.distance(tc.segments.begin()->first);

	    // We already compared (>=) those two values above, this must be
	    // positive or zero.

	    eng.data(fc, 
		     tc.segments.begin()->segment.begin() + unwanted,
		     tc.segments.begin()->segment.end());

	    tc.seq_expected = tc.segments.begin()->last;

	    // Remove the used segment.
	    tc.segments.erase(tc.segments.begin());

	    continue;

	}

	// PDU at start of queue was no use.  Bail.
	
	break;

    }
    
}

