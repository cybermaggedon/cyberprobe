
#include <unistd.h>
#include <iostream>
#include <list>

#include "reaper.h"

void reaper::run()
{
    
    while (running) {
	
	::sleep(1);

	lock.lock();

	// We can bail out of this loop if we're stopping.
	while (running) {

	    // This destruction may have resulted in some other
	    // objects self-reaping, so we can remove them.
	    self_lock.lock();

	    while (!self_list.empty()) {

		reapable* r = self_list.front();
		self_list.pop_front();
		
		self_lock.unlock();

		if (reap_map.find(r) != reap_map.end()) {
		    unsigned long cur_reap = reap_map[r];
		    reap_list.erase(std::pair<unsigned long,reapable*>(cur_reap,r));
		    reap_map.erase(r);
		}

		self_lock.lock();

	    }

	    self_lock.unlock();


	    if (reap_list.empty()) break;

	    unsigned long now = get_time();
	    unsigned long next = reap_list.begin()->first;

	    if (next <= now) {
		
		reapable* r = reap_list.begin()->second;

		reap_list.erase(std::pair<unsigned long,reapable*>(next, r));
		reap_map.erase(r);

		// Delete the item.

		r->reap();

		// It's important that the 'self' list is processed before
		// the reap map, otherwise we won't realise some objects have
		// gone away.

		// Try next item.
		continue;

	    }

	    // Done, bail out of loop.
	    break;

	}

	lock.unlock();

    }

}

