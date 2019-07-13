/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

 cybermon_qreader. Part of new queue implementation to address frequent cybermon
 crash caused due to limitation of lua threading.
 Reads q_entry from queue and send it to cybermon::cybermon_lua

****************************************************************************/

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
				   std::mutex& cqwrlock,
				   cybermon_qwriter& cqwriter) :
    cml(path), cqueue(cybermonq), mutex(cqwrlock), qwriter(cqwriter) {
    running = true;
    thr = nullptr;
}

// cybermon_qreader thread body - gets PDUs off the queue, and calls the cybermon lua handler.
void cybermon_qreader::run() {

    std::unique_lock<std::mutex> lock(mutex);

    // Loop until finished.
    while (running) {

	// At this point we hold the lock.

	//observed with out this sleep the containers consuming cpu
	if (cqueue.size() == 0) {
	    lock.unlock();
	    usleep(1000);
	    lock.lock();
	    continue;
	}

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

	// Get the lock.
	lock.lock();

    }

}

