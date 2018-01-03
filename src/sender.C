
#include "sender.h"

// Called to add packets to the queue.
void sender::deliver(const std::string& liid, // LIID
		     const_iterator& start,   // Start of packet
		     const_iterator& end)     // End of packet
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
    qpdu_ptr p = qpdu_ptr(new qpdu());
    p->msg_type = qpdu::PDU;
    p->pdu.assign(start, end);
    p->liid = liid;
    packets.push(p);

    // Wake up the sender's run method.
    cond.signal();

    // Done with the lock.
    lock.unlock();

}

// Called to add packets to the queue.
void sender::target_up(const std::string& liid,        // LIID
		       const tcpip::address& addr)     // Address
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

    address_ptr np;
    
    if (addr.universe == addr.ipv4) {
	const tcpip::ip4_address& addr4 = 
	    dynamic_cast<const tcpip::ip4_address&>(addr);
	np = address_ptr(new tcpip::ip4_address(addr4));
    } else {
    	const tcpip::ip6_address& addr6 = 
	    dynamic_cast<const tcpip::ip6_address&>(addr);
	np = address_ptr(new tcpip::ip6_address(addr6));
    }

    // Put a packet on the queue.
    qpdu_ptr p = qpdu_ptr(new qpdu());
    p->msg_type = qpdu::TARGET_UP;
    p->liid = liid;
    p->addr = np;
    packets.push(p);

    // Wake up the sender's run method.
    cond.signal();

    // Done with the lock.
    lock.unlock();

}

// Called to add packets to the queue.
void sender::target_down(const std::string& liid)        // LIID
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
    qpdu_ptr q = qpdu_ptr(new qpdu());
    q->msg_type = qpdu::TARGET_DOWN;
    q->liid = liid;
    packets.push(q);

    // Wake up the sender's run method.
    cond.signal();

    // Done with the lock.
    lock.unlock();

}

// Sender thread body - gets PDUs off the queue, and calls the handler.
void sender::run()
{

    // Get the lock.
    lock.lock();

    // Loop until finished.
    while (running) {

	// Loop until the input queue is empty.
	while (running && (packets.size() > 0)) {

	    // At this point we hold the lock.

	    // Take next packet off queue.
	    qpdu_ptr next = packets.front();
	    packets.pop();

	    // Got the packet, so the queue can unlock.
	    lock.unlock();
	    
	    // Keep trying to handle the PDU until handled without exception.
	    while (running) {

		try {
		    handle(next);
		    break;	// Out of while loop.
		} catch (std::exception& e) {
		    // Wait and retry.
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

// NHIS 1.1 sender thread body.
void nhis11_sender::handle(qpdu_ptr next)
{

    // Short-hand.
    const std::string& liid = next->liid;

    // NHIS 1.1 can only handle the PDUs.
    if (next->msg_type != qpdu::PDU) return;

    // FIXME: We could use the TARGET_UP and TARGET_DOWN messages
    // to close connections that aren't needed any more.

    // Loop until successful delivery.
    while (running) {

	// Loop forever until we're connected.
	while (running && 
	       (transport.find(liid) == transport.end())) {
	    try {
		if (tls) 
		    transport[liid].connect_tls(h, p, liid,
						params["key"],
						params["certificate"],
						params["chain"]);
		else
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

	    transport[liid].send(next->pdu);

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

}

// ETSI LI sender thread body.
void etsi_li_sender::handle(qpdu_ptr next)
{

    // Short-hand.
    const std::string& liid = next->liid;
    const std::vector<unsigned char>& pdu = next->pdu;
    const address_ptr addr = next->addr;

    // Loop until successful delivery.
    while (running) {

	// If we haven't handled the LIID before, map to a new
	// transport / mux
	if (muxes.find(liid) == muxes.end()) {

	    // Get next transport in the round robin
	    e_sender& transport = transports[cur_connect];

	    // Map LIID to the transport
	    std::pair<std::string,e_sender&> tp(liid, transport);
	    transport_map.insert(tp);

	    // Map LIID to mux
	    std::pair<std::string,e_mux> mp(liid,
					    e_mux(transports[cur_connect]));
	    muxes.insert(mp);
		
	    // Increment connection count, wrap at num_connects.
	    if (++cur_connect >= num_connects)
		cur_connect = 0;

	}

	// Get transport and mux.  Guaranteed to be allocated at this point.
	e_sender& transport = transport_map.find(liid)->second;
	e_mux& mux = muxes.find(liid)->second;
	
	// Loop forever until we're connected.
	while (running && !transport.connected()) {
	    try {
		if (tls) 
		    transport.connect_tls(h, p,
					  params["key"],
					  params["certificate"],
					  params["chain"]);
		else
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
	
	// Target is up.
	if (next->msg_type == qpdu::TARGET_UP) {
	    
	    // Describe the target connection.
	    try {
		
		std::string oper, country, net_elt, int_pt;
		std::string username;
		
		// Get metadata parameters
		oper = global_pars.get_parameter("operator", "unknown");
		country = global_pars.get_parameter("country", "XX");

		net_elt = global_pars.get_parameter("network_element." + liid,
						    "");
		if (net_elt == "")
		    net_elt = global_pars.get_parameter("network_element",
							"unknown");

		int_pt = global_pars.get_parameter("interception_point",
						   "unknown");
		username = global_pars.get_parameter("username." + liid,
						     "unknown");

		// Send connect IRI stuff.
		mux.target_connect(liid, *next->addr, 
				   oper, country, net_elt,
				   int_pt, username);

		// All done, break out of the 'while' loop.
		break;

	    } catch (std::exception& e) {
		// Didn't describe the connection.
		// Doesn't matter, we'll loop round and try it again.
		std::cerr << "ETSI LI connection to "
			  << h << ":" << p << " failed." << std::endl;
		std::cerr << "Will reconnect..." << std::endl;
		transport.close();
		::sleep(1);
	    }

	}

	// A PDU of data.
	if (next->msg_type == qpdu::PDU) {

	    // Send a PDU
	    try {

		// Fetch metadata parameters
		std::string oper, country, net_elt, int_pt;
		oper = global_pars.get_parameter("operator", "unknown");
		country = global_pars.get_parameter("country", "XX");

		net_elt = global_pars.get_parameter("network_element." + liid,
						    "");
		if (net_elt == "")
		    net_elt = global_pars.get_parameter("network_element",
							"unknown");

		int_pt = global_pars.get_parameter("interception_point",
						   "unknown");

		// Deliver packet.
		mux.target_ip(liid, pdu, oper, country, net_elt, 
			      int_pt);

		// Only break out of the loop on success.
		break;

	    } catch (...) {
		// Doesn't matter, we'll loop round and try it again.
		std::cerr << "ETSI LI connection to "
			  << h << ":" << p << " failed." << std::endl;
		std::cerr << "Will reconnect..." << std::endl;
		transport.close();
		::sleep(1);
	    }
	}

	// Target is down.
	if (next->msg_type == qpdu::TARGET_DOWN) {

	    // Describe target disconnection.
	    try {

		std::string oper, country, net_elt, int_pt;

		// Get metadata parameters
		oper = global_pars.get_parameter("operator", "unknown");
		country = global_pars.get_parameter("country", "XX");


		net_elt = global_pars.get_parameter("network_element." + liid,
						    "");
		if (net_elt == "")
		    net_elt = global_pars.get_parameter("network_element",
							"unknown");

		int_pt = global_pars.get_parameter("interception_point",
						   "unknown");

		// Send disconnect IRI stuff.
		mux.target_disconnect(liid, oper, country, net_elt,
				      int_pt);

		// All done, break out of the 'while' loop.
		break;

	    } catch (std::exception& e) {
		// Didn't describe the connection.
		// Doesn't matter, we'll loop round and try it again.
		std::cerr << "ETSI LI connection to "
			  << h << ":" << p << " failed." << std::endl;
		std::cerr << "Will reconnect..." << std::endl;
		transport.close();
		::sleep(1);
	    }

	}

    }

}
