/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

 cybermon_qreader. Part of new queue implementation to address frequent cybermon
 crash caused due to limitation of lua threading.
 Reads q_entry from queue and send it to cybermon::cybermon_lua

****************************************************************************/

#include <cybermon_qargs.h>
#include <cybermon_qreader.h>
#include <iostream>
#include <iomanip>
#include <map>
#include <stdint.h>

#include <boost/program_options.hpp>

#include <cybermon/engine.h>
#include <cybermon/context.h>
#include <cybermon/cybermon-lua.h>

using namespace cybermon;

cybermon_qreader::cybermon_qreader(const std::string& path,
				   std::queue<eptr>& cybermonq,
				   threads::mutex& cqwrlock,
				   cybermon_qwriter cqwriter) :
    cml(path), cqueue(cybermonq), lock(cqwrlock), qwriter(cqwriter) {
    running = true;
}

// cybermon_qreader thread body - gets PDUs off the queue, and calls the cybermon lua handler.
void cybermon_qreader::run() {

    // Loop until finished.
    while (running) {

	//observed with out this sleep the containers consuming cpu
	if (cqueue.size() == 0) {
	    usleep(1000);
	    continue;
	}

	// Get the lock.
	lock.lock();
	// At this point we hold the lock.

	// Take next packet off queue.
	eptr qentry = cqueue.front();
	cqueue.pop();

	// Null pointer indicates end of stream.
	if (!qentry) {
	    lock.unlock();
	    running = false;
	    break;
	}

	// Got the packet, so the queue can unlock.
	lock.unlock();


	try {
	    cml.event(qwriter, qentry);
	} catch (std::exception& e) {

	    std::cerr << "cybermon_qreader::run Exception: " << e.what()
		      << std::endl;
	}

    }

}

