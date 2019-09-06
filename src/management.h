
#ifndef MANAGEMENT_H
#define MANAGEMENT_H

#include <list>
#include <map>

#include "interface.h"
#include "endpoint.h"
#include "target.h"
#include "parameter.h"

#include <cyberprobe/network/socket.h>

namespace cyberprobe {

class management {

public:
    virtual ~management() {}

    // Modifies interface capture
    virtual void add_interface(const interface::spec& sp) = 0;

    // Modifies interface capture
    virtual void remove_interface(const interface::spec& sp) = 0;

    virtual void get_interfaces(std::list<interface::spec>& ii) = 0;

    // Modifies the target map to include a mapping from address to target.
    virtual void add_target(const target::spec& sp) = 0;

    // Removes a target mapping.
    virtual void remove_target(const target::spec& sp) = 0;

    // Fetch current target list.
    virtual void 
    get_targets(std::list<target::spec>& sp) = 0;

    // Adds an endpoint
    virtual void add_endpoint(const endpoint::spec&) = 0;

    // Removes an endpoint
    virtual void remove_endpoint(const endpoint::spec&) = 0;

    // Fetch current target list.
    virtual void get_endpoints(std::list<endpoint::spec>& info) = 0;

    // Add parameter.
    virtual void add_parameter(const parameter::spec& sp)
    = 0;

    // Remove parameter.
    virtual void remove_parameter(const parameter::spec& sp) = 0;

    // Get all parameters.
    virtual void get_parameters(std::list<parameter::spec>& lst) = 0;

};

};

#endif

