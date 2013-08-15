
#include <unistd.h>

#include <list>

#include "reaper.h"

void reaper::run()
{
    
    while (running) {
	
	::sleep(1);

	lock.lock();

	// We can bail out of this loop if we're stopping.
	while (running) {

	    if (reap_list.empty()) break;

	    unsigned long now = get_time();
	    unsigned long next = reap_list.begin()->first;

	    if (next <= now) {
		
		reapable* r = reap_list.begin()->second;
		
		reap_list.erase(std::pair<unsigned long,reapable*>(next, r));
		reap_map.erase(r);

		// Delete the item.
		r->reap();

		// This destruction may have resulted in some other
		// objects self-reaping, so we can remove them.
		self_lock.lock();

		for(std::list<reapable*>::iterator it = self_list.begin();
		    it != self_list.end();
		    it++) {
		    
		    if (reap_map.find(*it) != reap_map.end()) {
			unsigned long cur_reap = reap_map[*it];
			reap_list.erase(std::pair<unsigned long,reapable*>(cur_reap,*it));
			reap_map.erase(*it);
		    }

		}

		self_lock.unlock();

		// Try next item.
		continue;

	    }

	    // Done, bail out of loop.
	    break;

	}

	lock.unlock();

    }

}

