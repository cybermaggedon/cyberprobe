
#include <cyberprobe/probe/sender.h>

#include <condition_variable>
#include <mutex>

using namespace cyberprobe;

using direction = cyberprobe::protocol::direction;

// Called to add packets to the queue.
void sender::deliver(timeval tv,
		     std::shared_ptr<std::string> device, // Device
		     std::shared_ptr<std::string> network, // Network
                     direction dir, // To/from target.
		     const_iterator& start,   // Start of packet
		     const_iterator& end)     // End of packet
{

    // Get lock.
    std::unique_lock<std::mutex> lock(mutex);

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
    p->tv = tv;
    p->device = device;
    p->network = network;
    p->dir = dir;
    packets.push(p);

    // Wake up the sender's run method.
    cond.notify_one();

}

// Called to add packets to the queue.
void sender::target_up(std::shared_ptr<std::string> device,      // Device
		       std::shared_ptr<std::string> network,     // Network
		       const tcpip::address& addr)               // Address
{

    // Get lock.
    std::unique_lock<std::mutex> lock(mutex);

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
    p->device = device;
    p->network = network;
    p->addr = np;
    packets.push(p);

    // Wake up the sender's run method.
    cond.notify_one();

}

// Called to add packets to the queue.
void sender::target_down(std::shared_ptr<std::string> device,      // Device
			 std::shared_ptr<std::string> network)     // Network
{

    // Get lock.
    std::unique_lock<std::mutex> lock(mutex);

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
    q->device = device;
    q->network = network;
    packets.push(q);

    // Wake up the sender's run method.
    cond.notify_one();

}

// Sender thread body - gets PDUs off the queue, and calls the handler.
void sender::run()
{

    // Get the lock.
    std::unique_lock<std::mutex> lock(mutex);

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

}

// NHIS 1.1 sender thread body.
void nhis11_sender::handle(qpdu_ptr next)
{

    // Short-hand.
    const std::string& device = *(next->device);

    // Network is ignored, not used for NHIS.

    // NHIS 1.1 can only handle the PDUs.
    if (next->msg_type != qpdu::PDU) return;

    // FIXME: We could use the TARGET_UP and TARGET_DOWN messages
    // to close connections that aren't needed any more.

    // Loop until successful delivery.
    while (running) {

	// Loop forever until we're connected.
	while (running &&
	       (transport.find(device) == transport.end())) {
	    try {
		if (tls)
		    transport[device].connect_tls(h, p, device,
						params["key"],
						params["certificate"],
						params["chain"]);
		else
		    transport[device].connect(h, p, device);
		std::cerr << "NHIS 1.1 connection to "
			  << h << ":" << p << " for device "
			  << device << " established." << std::endl;
	    } catch (...) {
		// If fail, just for a sec, before the retry.
		transport.erase(device);
		::sleep(1);
	    }
	}

	if (!running) break;

	// Either:
	// - transmit the packet, OR
	// - on fail, close the connection and leave the loop to
	//   reconnect.
	try {

	    transport[device].send(next->pdu);

	    // Only break out of the loop on success.
	    break;

	} catch (...) {
	    std::cerr << "NHIS 1.1 connection for device " << device
		      << " failed." << std::endl;
	    std::cerr << "Will reconnect..." << std::endl;
	    transport[device].close();
	    transport.erase(device);
	    ::sleep(1);
	}

    }

}

// ETSI LI sender thread body.
void etsi_li_sender::handle(qpdu_ptr next)
{

    // Short-hand.
    const std::string& device = *(next->device);
    const std::string& network = *(next->network);
    const std::vector<unsigned char>& pdu = next->pdu;
    const address_ptr addr = next->addr;

    // Loop until successful delivery.
    while (running) {

	// If we haven't handled the device before, map to a new
	// transport / mux
	if (muxes.find(device) == muxes.end()) {

	    // Get next transport in the round robin
	    e_sender& transport = transports[cur_connect];

	    // Map device to the transport
	    std::pair<std::string,e_sender&> tp(device, transport);
	    transport_map.insert(tp);

	    // Map device to mux
	    std::pair<std::string,e_mux> mp(device,
					    e_mux(transports[cur_connect]));
	    muxes.insert(mp);

	    // Increment connection count, wrap at num_connects.
	    if (++cur_connect >= num_connects)
		cur_connect = 0;

	}

	// Get transport and mux.  Guaranteed to be allocated at this point.
	e_sender& transport = transport_map.find(device)->second;
	e_mux& mux = muxes.find(device)->second;

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

	std::string oper, country, net_elt, int_pt;
	std::string username;

	// Get metadata parameters
	oper = global_pars.get_parameter("operator", "unknown");
	country = global_pars.get_parameter("country", "");

	if (network != "")
	    net_elt = network;
	else {
	    if (net_elt == "")
		net_elt = global_pars.get_parameter("network_element",
						    "");
	}

	int_pt = global_pars.get_parameter("interception_point",
					   "");

	// Target is up.
	if (next->msg_type == qpdu::TARGET_UP) {

	    // Describe the target connection.
	    try {

		username = global_pars.get_parameter("username." + device, "");

		// Send connect IRI stuff.
		mux.target_connect(device, *next->addr,
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

		// Deliver packet.
		mux.target_ip(next->tv, device, pdu, oper, country, net_elt,
			      int_pt, next->dir);

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

		// Send disconnect IRI stuff.
		mux.target_disconnect(device, oper, country, net_elt,
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
