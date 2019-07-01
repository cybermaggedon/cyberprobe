/*
 * cybermon_qreader.h
 *
 *  Created on: 23 Jun 2017
 *      Author: venkata
 */

#ifndef CYBERMON_QREADER_H_
#define CYBERMON_QREADER_H_

#include <queue>
#include <cybermon_qargs.h>
#include <cybermon_qwriter.h>
#include <cybermon/event.h>

namespace cybermon {

    class cybermon_qreader {

        typedef std::shared_ptr<event::event> eptr;

    private:
	cybermon_lua cml;
	std::thread* thr;

    protected:
	// State: true if we're running, false if we've been asked to stop.
	bool running;

        std::queue<eptr>& cqueue;

	std::mutex& mutex;

    public:

	// Constructor
	cybermon_qreader(const std::string& path,
			 std::queue<eptr>& cybermonq,
			 std::mutex& cqwrlock, cybermon_qwriter& cqwriter);

	cybermon_qwriter& qwriter;

	// Thread body.
	virtual void run();

	// Destructor.
	virtual ~cybermon_qreader() {
	    delete thr;
	}

	virtual void stop() {
	    running = false;
	    join();
	}

	virtual void join() {
	    if (thr) thr->join();
	}

	virtual void start() {
	    thr = new std::thread(&cybermon_qreader::run, this);
	}

    };

};

#endif /* CYBERMON_QREADER_H_ */
