
// Resource management.  This set of classes is used to provide dynamic
// configuration-file-based management of resources.  To use this stuff,
// you need to provide:
//
// - At least one class derived from the specification class.  These
//   specifications described resources - they contain the information about
//   a resource.  You have to implement the get_type and get_hash
//   methods, and also add the information describing your resource.
//
// - At least one class derived from the resource_manager class.  This should
//   implement the 'read' method, which will read the configuration file
//   and return specifications.  You should also implement the 'create'
//   method to create resources.
//
// - At least one class derived from the resource class.  These are
//   instantiations of specifications.  You have to implement the 'start'
//   and 'stop' methods to get it to start and stop the resource.
//
// You then call the 'check' method on your resource manager periodically
// to get it to check the configuration file for changes.

#ifndef CYBERMON_RESOURCE_H
#define CYBERMON_RESOURCE_H

#include <cybermon/thread.h>
#include <cybermon/specification.h>

#include <string>
#include <list>
#include <map>

namespace cybermon {

// Resource base class.  Resources are an implementation of a specification.
// Then can be started and stopped.
class resource {
  public:
    
    // Start the resource.
    virtual void start() = 0;

    // Stop the resource.
    virtual void stop() = 0;

    // Destructor.
    virtual ~resource() {}
};

// Resource manager class.  Reads a configuration file when the 'update'
// method is called, converts the configuration file into a set of
// specifications, then starts/stops the resources according to changes
// in the specifications.
class resource_manager {

private:

    // Time of last file update.
    long last_update;

protected:

    // Returns true if the file has been modified since the specified
    // timestamp.
    virtual bool newer(const std::string& file, long& tm);

    // Resources, indexed by specification hash.
    std::map<std::string, resource*> resources;

    // Specifications, indexed by specification hash.
    std::map<std::string, specification*> specs;

    // A lock governing multi-threaded access to the above.
    threads::mutex lock;

    // Implement a set of resource changes, starting and stopping resources
    // to meet the new specification list.
    virtual void update(std::map<std::string, specification*>& upd);

protected:

    // Users should implement this - it knows how to turn specifications
    // into resources.
    virtual resource* create(specification& spec) = 0;

    // Users should implement this method to implement configuration
    // file scanning.
    virtual void read(const std::string& file,
		      std::list<specification*>&) = 0;

public:

    // Constructor.
    resource_manager() { 
	// Set last update time to 1970, making certain the configuration
	// file will be read on next update.
	last_update = 0;
    }

    // Destructor.
    virtual ~resource_manager() { }

    // Called to initiate a re-scan of the configuration file.  You
    // should probably call the 'check' method so that the configuration
    // file is re-scanned only when it is known that it has changed.
    virtual void update(const std::string& file);

    // Initiates a check of the configuration file timestamp.  If the
    // configuration file has changed, will initiate an update.
    void check(const std::string& file);

    // Reads the contents of a file into a string.
    static void get_file(const std::string& f, std::string& str);

};

};

#endif

