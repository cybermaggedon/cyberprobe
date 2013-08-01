
#include "sender.h"

// Called to add packets to the queue.
void sender::deliver(const std::string& liid, // LIID
		     const_iterator& start,   // Start of packet
		     const_iterator& end,     // End of packet
		     const tcpip::address& addr)
{

    // Get lock.
    lock.lock();

    // Wait until there's space on the queue.
    while (running && (packets.size() > max_packets)) {

	// Give up lock so that packets can be delivered.
	lock.unlock();
	
	// Sleep for a sec.
	::sleep(1);

	// Get lock in order to check loop condition.
	lock.lock();

    }

    // If we've been waiting, and the sender is now exiting, can bail out.
    if (!running) { lock.unlock(); return; }

    // Put a packet on the queue.
    packets.push_back(pdu());
    packets.back().pdu.assign(start, end);
    packets.back().liid = liid;

    if (addr.universe == addr.ipv4) {
	const tcpip::ip4_address& addr4 = 
	    static_cast<const tcpip::ip4_address&>(addr);
	packets.back().addr = new tcpip::ip4_address(addr4);
    } else {	    
	const tcpip::ip6_address& addr6 = 
	    static_cast<const tcpip::ip6_address&>(addr);
	packets.back().addr = new tcpip::ip6_address(addr6);
    }

    // Wake up the sender's run method.
    cond.signal();

    // Done with the lock.
    lock.unlock();

}

// NHIS 1.1 sender thread body.
void nhis11_sender::run()
{

    // Get the lock.
    lock.lock();

    // Loop until finished.
    while (running) {

	// Loop until the input queue is empty.
	while (running && (packets.size() > 0)) {

	    // At this point we hold the lock.

	    // Take next packet off queue.
	    pdu next;
	    std::swap(packets.front(), next);
	    packets.pop_front();

	    // Short-hand.
	    std::string& liid = next.liid;

	    // Don't need this IP address.
	    delete next.addr;

	    // Got the packet, so the queue can unlock.
	    lock.unlock();

	    // Loop until successful delivery.
	    while (running) {

		// Loop forever until we're connected.
		while (running && 
		       (transport.find(liid) == transport.end())) {
		    try {
			transport[liid].connect(h, p, liid);
			std::cerr << "NHIS 1.1 connection to " 
				  << h << ":" << p << " for LIID "
				  << liid << " established." << std::endl;
		    } catch (...) {
			// If fail, just for a sec, before the retry.
			transport.erase(liid);
			::sleep(1);
		    }
		}

		if (!running) break;

		// Either:
		// - transmit the packet, OR
		// - on fail, close the connection and leave the loop to
		//   reconnect.
		try {

		    transport[liid].send(next.pdu);

		    // Only break out of the loop on success.
		    break;

		} catch (...) {
		    std::cerr << "NHIS 1.1 connection for LIID " << liid
			      << " failed." << std::endl;
		    std::cerr << "Will reconnect..." << std::endl;
		    transport[liid].close();
		    transport.erase(liid);
		    ::sleep(1);
		}

	    }

	    // Grab the lock so we can check the queue size on the loop
	    // condition.
	    lock.lock();

	}

	// May have jumped out of the loop because the thread is stopping,
	// so, leave.
	if (!running) break;

	// The queue is empty, wait on the condition variable for more
	// packets.
	cond.wait(lock);

    }

    // We're done, but holding the lock.  Give it up!
    lock.unlock();

}

// ETSI LI sender thread body.
void etsi_li_sender::run()
{

    // Get the lock.
    lock.lock();

    // Loop until finished.
    while (running) {

	// Loop until the input queue is empty.
	while (running && (packets.size() > 0)) {

	    // At this point we hold the lock.

	    // Take next packet off queue.
	    pdu next;
	    std::swap(packets.front(), next);
	    packets.pop_front();

	    // Short-hand.
	    std::string& liid = next.liid;

	    // Got the packet, so the queue can unlock.
	    lock.unlock();

	    // Loop until successful delivery.
	    while (running) {

		// Loop forever until we're connected.
		while (running && !transport.connected()) {
		    try {
			transport.connect(h, p);
			std::cerr << "ETSI LI connection to " 
				  << h << ":" << p 
				  << " established." << std::endl;
		    } catch (...) {
			// If fail, just for a sec, before the retry.
			::sleep(1);
		    }
		}

		if (!running) break;


		// Either:
		// - transmit the packet, OR
		// - on fail, close the connection and leave the loop to
		//   reconnect.
		try {

		    // Have we transmitted this LIID before?  If not, should
		    // declare the connection.
		    if (!setup[liid]) {
		    
			// Describe the target connection.
			try {

			    std::string oper, country, net_elt, int_pt;
			    std::string username;

			    // Get metadata parameters
			    oper = pars.get_parameter("operator", "unknown");
			    country = pars.get_parameter("country", "XX");
			    net_elt = pars.get_parameter("network_element",
							 "unknown");
			    int_pt = pars.get_parameter("interception_point",
							"unknown");
			    username = pars.get_parameter("username." + liid,
							  "unknown");

			    // Send connect IRI stuff.
			    mux.target_connect(liid, *next.addr, 
					       oper, country, net_elt,
					       int_pt, username);

			    // Setup successful, we're in business to send
			    // IP packets.
			    setup[liid] = true;

			} catch (std::exception& e) {
			    // Didn't describe the connection.  Make sure
			    // it gets sent next time.
			    setup[liid] = false;
			}

		    }

		    // Fetch metadata parameters
		    std::string oper, country, net_elt, int_pt;
		    oper = pars.get_parameter("operator", "OPRunknown");
		    country = pars.get_parameter("country", "XX");
		    net_elt = pars.get_parameter("network_element",
						 "unknown");
		    int_pt = pars.get_parameter("interception_point",
						"unknown");

		    // Deliver packet.
		    mux.target_ip(liid, next.pdu, oper, country, net_elt, 
				  int_pt);

		    // Only break out of the loop on success.
		    break;

		} catch (...) {
		    std::cerr << "ETSI LI connection to "
			      << h << ":" << p << " failed." << std::endl;
		    std::cerr << "Will reconnect..." << std::endl;
		    transport.close();
		    ::sleep(1);
		}

	    }

	    // Grab the lock so we can check the queue size on the loop
	    // condition.
	    lock.lock();

	}

	// May have jumped out of the loop because the thread is stopping,
	// so, leave.
	if (!running) break;

	// The queue is empty, wait on the condition variable for more
	// packets.
	cond.wait(lock);

    }

    // We're done, but holding the lock.  Give it up!
    lock.unlock();

}
