
#include <cyberprobe/resources/resource.h>
#include <string>
#include <iostream>
#include <stdexcept>

#include <unistd.h>
#include <assert.h>

using namespace cyberprobe::resources;

// Records which resources are running.  The resources mess with this
// directly so we know.
std::map<std::string, bool> running;

// Lion spec, doesn't do anything useful.
class lion_spec : public specification {
public:
    std::string name;
    lion_spec(const std::string& name) : name(name) {}
    std::string get_hash() const { return name; }
    std::string get_type() const { return "lion"; }
};

// Tiger spec, doesn't do anything useful.
class tiger_spec : public specification {
public:
    std::string name;
    tiger_spec(const std::string& name) : name(name) {}
    std::string get_hash() const { return name; }
    std::string get_type() const { return "tiger"; }
};

// Lion resource
class lion : public resource {
public:
    lion(const lion_spec& spec) : name(spec.name) {}
    std::string name;
    void start() { 
	std::cout << "Start lion resource " << name << std::endl;
	running["lion:" + name] = true;
    }
    void stop() { 
	std::cout << "Stop lion resource " << name << std::endl;
	running.erase("lion:" + name);
    }
};

// Tiger resource
class tiger : public resource {
public:
    tiger(const tiger_spec& spec) : name(spec.name) {}
    std::string name;
    void start() { 
	std::cout << "Start tiger resource " << name << std::endl;
	running["tiger:" + name] = true;
    }
    void stop() { 
	std::cout << "Stop tiger resource " << name << std::endl;
	running.erase("tiger:" + name);
    }
};

// Resource manager.  Creates lion and tiger resources.  The 'read' method
// ignores the configuration file and just has some hard-coded logic for
// creating resources.
class test_resource_mgr : public resource_manager {
private:
    virtual bool newer(const std::string& file, long& tm) { return true; }

protected:

    // Resource creator.
    virtual resource* create(specification& spec) {

	if (spec.get_type() == "lion") {
	    lion_spec& s = dynamic_cast<lion_spec&>(spec);
	    return new lion(s);
	}

	if (spec.get_type() == "tiger") {
	    tiger_spec& s = dynamic_cast<tiger_spec&>(spec);
	    return new tiger(s);
	}

	throw std::runtime_error("Don't know that type.");

    }

    // Reads the (non-existent) configuration file.
    virtual void read(const std::string& file,
		      std::list<specification*>& specs) {

	static bool here = false;

	// Second time through this, returns only a single lion resource.
	if (here) {
	    specs.push_back(new lion_spec("lion"));
	    return;
	}

	here = true;

	// First time through, creates three resources.
	specs.push_back(new lion_spec("lion"));
	specs.push_back(new lion_spec("lioness"));
	specs.push_back(new tiger_spec("tiger"));

    }
};

int main(int argc, char** argv)
{

    test_resource_mgr mgr;

    // Start off with no running resources.
    assert(running.size() == 0);

    // Check the (non-existent) configuration file.
    mgr.check("config.txt");

    // Check there are three resources.
    assert(running["lion:lion"] == true);
    assert(running["lion:lioness"] == true);
    assert(running["tiger:tiger"] == true);
    assert(running.size() == 3);
    
    // Check the (non-existent) configuration file again.
    mgr.check("config.txt");

    // Check there is one resources.
    assert(running["lion:lion"] == true);
    assert(running.size() == 1);

}

