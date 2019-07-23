
#include "delivery.h"
#include "parameter.h"

namespace parameter {
    
    // Start method, change the delivery engine mapping.
    void parameter::start() { 
        deliv.add_parameter(sp);
        std::cerr << "Added parameter " << sp.key << "=" << sp.val 
                  << std::endl;
    }

    // Stop method, remove the mapping.
    void parameter::stop() { 
        deliv.remove_parameter(sp);
        std::cerr << "Removed parameter " << sp.key << "=" << sp.val 
                  << std::endl;
    }

};
