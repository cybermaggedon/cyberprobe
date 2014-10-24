
////////////////////////////////////////////////////////////////////////////
//
// CONFIGURATION FILE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CONFIG_H
#define CONFIG_H

#include <cybermon/resource.h>

#include "delivery.h"

// Configuration file manager.
class config_manager : public cybermon::resource_manager {
private:

    // Delivery engine.
    delivery& deliv;

    // Filter expression.
    std::string filter;

protected:

    // Read the configuration file.
    virtual void read(const std::string& file,
		      std::list<cybermon::specification*>&);

    // Convert a specification into a resource.
    virtual cybermon::resource* create(cybermon::specification& spec);

public:

    // Set filter for packet capture.
    void set_filter(const std::string& s) { filter = s; }

    // Constructor.
    config_manager(delivery& d) : deliv(d) { }

};

#endif

