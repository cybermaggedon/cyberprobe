
////////////////////////////////////////////////////////////////////////////
//
// CONFIGURATION FILE
//
////////////////////////////////////////////////////////////////////////////

#ifndef CONFIG_H
#define CONFIG_H

#include "resource.h"
#include "delivery.h"

// Configuration file manager.
class config_manager : public resource_manager {
private:

    // Delivery engine.
    delivery& deliv;

    // Filter expression.
    std::string filter;

protected:

    // Read the configuration file.
    virtual void read(const std::string& file,
		      std::list<specification*>&);

    // Convert a specification into a resource.
    virtual resource* create(specification& spec);

public:

    // Set filter for packet capture.
    void set_filter(const std::string& s) { filter = s; }

    // Constructor.
    config_manager(delivery& d) : deliv(d) { }

};

#endif

