
#ifndef CYBERMON_REAPER_H
#define CYBERMON_REAPER_H

#include <map>
#include <set>
#include <list>

#include <cybermon/thread.h>

class reapable;

class watcher {
public:
    virtual ~watcher() {}
    virtual unsigned long get_time() = 0;
    virtual void set_ttl(reapable& r, unsigned long ttl) = 0;
    virtual void unset_ttl(reapable& r) = 0;
    virtual void self_reaped(reapable& r) = 0;
};

class reapable {

public:
    watcher& r;

    reapable(watcher& r) : r(r) {
    }

    void set_ttl(unsigned long ttl) { r.set_ttl(*this, ttl); }
    void unset_ttl(unsigned long ttl) { r.set_ttl(*this, ttl); }

    virtual ~reapable() {
	// This removes me from the reap lists in the watcher.  I no longer
	// need to be reaped, see?
	r.self_reaped(*this);
    }

    virtual void reap() = 0;

};

class reaper : public threads::thread, public watcher {
private:
    
    threads::mutex lock;

    std::map<reapable*,unsigned long> reap_map;
    std::set< std::pair<unsigned long,reapable*> > reap_list;

    threads::mutex self_lock; // Lock for self_reaped
    std::list<reapable*> self_list;

    bool running;

public:
    void run();

    reaper() { running = true; }

    virtual void self_reaped(reapable& r) {
	self_lock.lock();
	self_list.push_back(&r);
	self_lock.unlock();
    }

    virtual ~reaper() {}

    virtual unsigned long get_time() {
	unsigned long l = ::time(0);
	return l;
    }

    virtual void set_ttl(reapable& r, unsigned long ttl) {
	reapable* rp = &r;

	lock.lock();

	if (reap_map.find(rp) != reap_map.end()) {
	    unsigned long cur_reap = reap_map[rp];
	    reap_list.erase(std::pair<unsigned long,reapable*>(cur_reap, rp));
	}

	unsigned long new_reap = get_time() + ttl;
	
	reap_map[rp] = new_reap;
	reap_list.insert(std::pair<unsigned long,reapable*>(new_reap, rp));

	lock.unlock();

    }

    virtual void unset_ttl(reapable& r) {

	reapable* rp = &r;

	lock.lock();

	if (reap_map.find(rp) != reap_map.end()) {
	    unsigned long cur_reap = reap_map[rp];
	    reap_list.erase(std::pair<unsigned long,reapable*>(cur_reap, rp));
	    reap_map.erase(rp);
	}

	lock.unlock();

    }

    void stop() { running = false; }

};

#endif

