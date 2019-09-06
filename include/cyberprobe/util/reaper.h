
#ifndef CYBERMON_REAPER_H
#define CYBERMON_REAPER_H

#include <map>
#include <set>
#include <list>
#include <thread>
#include <mutex>

namespace cyberprobe {

namespace util {

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

class reaper : public watcher {
private:
    
    std::mutex mutex;

    std::map<reapable*,unsigned long> reap_map;
    std::set< std::pair<unsigned long,reapable*> > reap_list;

    std::mutex self_mutex; // Lock for self_reaped
    std::list<reapable*> self_list;

    bool running;

    std::thread* thr;

public:
    void run();

    reaper() { running = true; }

    virtual void self_reaped(reapable& r) {
	std::lock_guard<std::mutex> lock(self_mutex);
	self_list.push_back(&r);
    }

    virtual ~reaper() {}

    virtual unsigned long get_time() {
	unsigned long l = ::time(0);
	return l;
    }

    virtual void set_ttl(reapable& r, unsigned long ttl) {
	reapable* rp = &r;

	std::lock_guard<std::mutex> lock(mutex);

	if (reap_map.find(rp) != reap_map.end()) {
	    unsigned long cur_reap = reap_map[rp];
	    reap_list.erase(std::pair<unsigned long,reapable*>(cur_reap, rp));
	}

	unsigned long new_reap = get_time() + ttl;
	
	reap_map[rp] = new_reap;
	reap_list.insert(std::pair<unsigned long,reapable*>(new_reap, rp));

    }

    virtual void unset_ttl(reapable& r) {

	reapable* rp = &r;

	std::lock_guard<std::mutex> lock(mutex);

	if (reap_map.find(rp) != reap_map.end()) {
	    unsigned long cur_reap = reap_map[rp];
	    reap_list.erase(std::pair<unsigned long,reapable*>(cur_reap, rp));
	    reap_map.erase(rp);
	}

    }

    void stop() {
	running = false;
	join();
    }

    virtual void start() {
	thr = new std::thread(&reaper::run, this);
    }

    virtual void join() {
	if (thr)
	    thr->join();
    }
    
};

};

};

#endif

