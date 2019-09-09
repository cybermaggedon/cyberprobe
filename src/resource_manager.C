
#include <cyberprobe/resources/resource.h>

#include <sys/stat.h>

#include <iostream>
#include <iterator>
#include <algorithm>
#include <set>
#include <fstream>

#include <string>

using namespace cyberprobe::resources;

void resource_manager::update(const std::string& file)
{
    
    // Load the resource specifications.

    // We re-read the resource specs to this strucutre, then implement the
    // changes.
    std::list<specification*> upd_list;
    std::map<std::string, specification*> upd;

    

    // Load new resource definitions.
    read(file, upd_list);


    // dedup resource definitions (have to be careful we don't leak)
    for (std::list<specification*>::iterator it = upd_list.begin(); it != upd_list.end(); it++) {
        std::string hash = (*it)->get_hash();
        if (upd.find(hash) == upd.end()) {
            upd[hash] = *it;
        }
        else {
            delete *it;

        }
    }

    // Implement.
    update(upd);

}

void resource_manager::update(std::map<std::string, specification*>& upd)
{

    // Take lock.
    lock.lock();

    // A set of 'old' and 'new' hashes.
    std::set<std::string> old_hashes, new_hashes;
    
    ////////////////////////////////////////////////////////////////////////
    // Do a set difference to work out the difference between the two
    // resouce sets.
    ////////////////////////////////////////////////////////////////////////
    
    // Create a list of hashes for the existing resource set.
    for(std::map<std::string, specification*>::iterator it = specs.begin();
	it != specs.end();
	it++)
	old_hashes.insert(it->first);

    // Create a list of hashes for the new resource set.
    for(std::map<std::string, specification*>::iterator it = upd.begin();
	it != upd.end();
	it++)
	new_hashes.insert(it->first);

    // A set for the hashes of sources which are no longer in the config
    // file.  And an insert iterator.
    std::set<std::string> going;
    std::insert_iterator<std::set<std::string> > 
	going_ins(going, going.begin());
    
    // A set for the hashes of sources which are new since the last time we
    // looked.  And an insert iterator.
    std::set<std::string> coming;
    std::insert_iterator<std::set<std::string> > 
	coming_ins(coming, coming.begin());
    
    // Set difference to get the list of hashes of sources to delete.
    set_difference(old_hashes.begin(), old_hashes.end(),
		   new_hashes.begin(), new_hashes.end(),
		   going_ins);
    
    // Set difference to get the list of hashes of sources to create.
    set_difference(new_hashes.begin(), new_hashes.end(),
		   old_hashes.begin(), old_hashes.end(),
		   coming_ins);

    ////////////////////////////////////////////////////////////////////////
    // Implement the resource changes.
    ////////////////////////////////////////////////////////////////////////

    // Go through the 'delete' list.
    for(std::set<std::string>::iterator it = going.begin();
	it != going.end();
	it++) {

	// Stop the resource and delete it.
	if (resources.find(*it) != resources.end()) {

	    // Stop the resource.
	    resources[*it]->stop();

	    // Delete the thread.
	    delete resources[*it];

	    // Erase from the thread list.
	    resources.erase(*it);

	}

	// Delete the resource specification.
        delete specs[*it]; 
	specs.erase(*it);

    }

    // Go through the 'create' list.
    for(std::set<std::string>::iterator it = coming.begin();
	it != coming.end();
	it++) {

	// Add new resource spec to the map
	specs[*it] = upd[*it];

        // remove it from upd so it won't get deleted during tidy
        upd.erase(*it);
	
	// Create the resource.
	try {
	    resources[*it] = create(*(specs[*it]));
	} catch (std::exception& e) {
#ifdef LOGGING
	    std::cerr << "Failed to create resource: "
		      << e.what()
		      << std::endl;
#endif
	    resources.erase(*it);
	    continue;
	}

	// Start the thread.
	try {
	    resources[*it]->start();
	} catch (std::exception& e) {
	    std::cerr << "Resource failed to start: " << e.what()
		      << std::endl;
	    delete resources[*it];
	    resources.erase(*it);
	    continue;
	}

    }

    // Tidy up the unchanged specs
    for(std::map<std::string,specification*>::iterator it = upd.begin();
	it != upd.end();
	it++) {
        delete it->second;
    }
    upd.clear();

    lock.unlock();

}

bool resource_manager::newer(const std::string& file, long& tm)
{
    
    struct stat buf;

    int ret = ::stat(file.c_str(), &buf);
    if (ret < 0)
	// Er... what to do?
	return true;

    if (buf.st_mtime > tm) {
	tm = buf.st_mtime;
	return true;
    }

    return false;

}

void resource_manager::check(const std::string& file)
{
  
    if (newer(file, last_update))
	update(file);

}

void resource_manager::get_file(const std::string& f, std::string& data)
{
    
    std::ifstream in(f.c_str());
    const int buflen = 8192;
    char buf[buflen];

    while(in) {
	in.read(buf, buflen);
	int got = in.gcount();
	data.append(buf, got);
    }

}
