
////////////////////////////////////////////////////////////////////////////
//
// CONFIGURATION FILE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <cyberprobe/resources/resource.h>
#include <cyberprobe/probe/delivery.h>

namespace cyberprobe {

namespace probe {

// Configuration file manager.
class config_manager : public resources::resource_manager {
private:

    // Delivery engine.
    delivery& deliv;

    // Filter expression.
    std::string filter;

protected:

    // Read the configuration file.
    virtual void read(const std::string& file,
		      std::list<resources::specification*>&);

    // Convert a specification into a resource.
    virtual resources::resource* create(resources::specification& spec);

public:

    // Set filter for packet capture.
    void set_filter(const std::string& s) { filter = s; }

    // Constructor.
    config_manager(delivery& d) : deliv(d) { }

};

}

}

#endif

