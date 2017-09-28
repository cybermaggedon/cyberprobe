/*
 * cybermon_qreader.h
 *
 *  Created on: 23 Jun 2017
 *      Author: venkata
 */

#ifndef CYBERMON_QREADER_H_
#define CYBERMON_QREADER_H_

#include <cybermon/thread.h>
#include <queue>
#include <cybermon_qargs.h>
#include <cybermon_qwriter.h>

namespace cybermon {

    class cybermon_qreader: public threads::thread {
      private:
	cybermon_lua cml;
      protected:
	// State: true if we're running, false if we've been asked to stop.
	bool running;
      public:
	// Constructor
	cybermon_qreader(const std::string& path,
			 std::queue<q_entry*>& cybermonq,
			 threads::mutex& cqwrlock, cybermon_qwriter cqwriter);

	cybermon_qwriter qwriter;

	std::queue<q_entry*>& cqueue;

	threads::mutex& lock;

	// Thread body.
	virtual void run();

	// Destructor.
	virtual ~cybermon_qreader() {
	}

    };

};

#endif /* CYBERMON_QREADER_H_ */
