
#include <iostream>
#include <string>
#include <boost/shared_ptr.hpp>

#include "reaper.h"

class thing : public reapable {
public:

    std::string name;

    std::map<std::string, boost::shared_ptr<thing> >& parent;

    unsigned long ttl;

    thing(grim& g, 
	  std::map<std::string, boost::shared_ptr<thing> >& p,
	  const std::string& name,
	  unsigned long ttl) : reapable(g), parent(p) {
	this->name = name;
	set_ttl(ttl);
	this->ttl = ttl;
	std::cerr << "Thing '" << name << "' is created." << std::endl;
    }

    void use() {
	reapable::set_ttl(ttl);
    }

    void reap() {
	std::cerr << "Thing '" << name << "' time is up." << std::endl;
	parent.erase(name);
    }

    virtual ~thing() {
	std::cerr << "Thing '" << name << "' desctroyed." << std::endl;
    }

};

int main(int argc, char** argv) {
    
    std::map<std::string,boost::shared_ptr<thing> > things;

    reaper r;

    r.start();
 
    boost::shared_ptr<thing> p;
    p = boost::shared_ptr<thing>(new thing(r, things, "thing.1", 6));
    things["thing.1"] = p;

    p = boost::shared_ptr<thing>(new thing(r, things, "thing.2", 8));
    things["thing.2"] = p;

    p = boost::shared_ptr<thing>(new thing(r, things, "thing.3", 7));
    things["thing.3"] = p;

    p = boost::shared_ptr<thing>(new thing(r, things, "thing.4", 6));
    things["thing.4"] = p;

    p = boost::shared_ptr<thing>();

    while (1) {

	things["thing.1"]->use();

	std::cerr << "Inventory: ";
	for(std::map<std::string,boost::shared_ptr<thing> >::iterator it =
		things.begin();
	    it != things.end();
	    it++) {
	    std::cerr << it->first << " ";
	}
	std::cerr << std::endl;

	std::cerr << "Sleeping..." << std::endl;
	::sleep(2);
    }

}

