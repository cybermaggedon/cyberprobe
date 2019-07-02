/*
 * cybermon_qwriter.h
 *
 *  Created on: 21 Jun 2017
 *      Author: venkata
 */

#ifndef CYBERMON_QWRITER_H_
#define CYBERMON_QWRITER_H_

#include <cybermon/cybermon-lua.h>
#include <cybermon/engine.h>
#include <cybermon_qargs.h>
#include <cybermon/tls_handshake_protocol.h>
#include <cybermon/event.h>

#include <queue>
#include <vector>

namespace cybermon {

    typedef std::shared_ptr<event::event> event_ptr;

    class cybermon_qwriter: public engine {

    public:


	// Constructor
        cybermon_qwriter(const std::string& path,
			 std::queue<event_ptr>& cybermonq,
			 std::mutex& cqwrlock);
	// Destructor.
	virtual ~cybermon_qwriter() {
	}

	std::queue<event_ptr>& cqueue;

	std::mutex& lock;

	virtual void handle(std::shared_ptr<event::event>);

	virtual void close();

	// Max size of queue.
	static const int q_limit = 1000;

	virtual void push(std::shared_ptr<event::event> e) {
	    lock.lock();

	    // Sleep until queue is below the queue limit.
	    while (cqueue.size() >= q_limit) {
		lock.unlock();
		usleep(10);
		lock.lock();
	    }

	    cqueue.push(e);
	    lock.unlock();
	}

    };

};

#endif /* CYBERMON_QWRITER_H_ */
