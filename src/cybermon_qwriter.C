/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

 cybermon_qwriter. Part of new queue implementation to address frequent cybermon
 crash caused due to limitation of lua threading.
 Creates args for different protocols and put in to q_entry to add in to a queue

****************************************************************************/

#include <cybermon_qwriter.h>
#include <cybermon_qargs.h>

#include <iostream>
#include <iomanip>
#include <map>
#include <memory>

#include <boost/program_options.hpp>

#include <cybermon/engine.h>
#include <cybermon/monitor.h>
#include <cybermon/etsi_li.h>
#include <cybermon/packet_capture.h>
#include <cybermon/context.h>
#include <cybermon/cybermon-lua.h>
#include <cybermon/event.h>
#include <cybermon/event_implementations.h>

using namespace cybermon;

cybermon_qwriter::cybermon_qwriter(const std::string& path,
				   std::queue<event_ptr>& cybermonq,
				   threads::mutex& cqwrlock) :
    cqueue(cybermonq), lock(cqwrlock) {
}

void cybermon_qwriter::handle(std::shared_ptr<event::event> ev)
{
    try {
      	push(ev);
    } catch (std::exception& e) {
	std::cerr << "Error: " << e.what() << std::endl;
    }
}

//to signal cybermon_qreader to stop
void cybermon_qwriter::close() {

    timeval tv;

    // Put null pointer on queue to indicate end of stream.
    push(std::shared_ptr<cybermon::event::event>(0));

}
