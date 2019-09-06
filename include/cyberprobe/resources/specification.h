
#ifndef CYBERPROBE_SPECIFICATION_H
#define CYBERPROBE_SPECIFICATION_H

#include <string>

namespace cyberprobe {

    class specification {
    public:
    
        // Resources have a hash which is used to work out when their
        // configuration changes.  This should return a string, which changes
        // when any parts of the resource description change.  Doesn't actually
        // have to be a hash.
        virtual std::string get_hash() const = 0;
    
        // Returns a string describing the type of resource.  Can be used in
        // resource_manager::create to work out which resource to create
        // for a specification.  Other than that, not used.
        virtual std::string get_type() const = 0;
    
        // Destructor.
        virtual ~specification() {}

        // Used to compare resource by comparing their hashes.
        virtual bool operator<(specification& other) {
            return get_hash() < other.get_hash();
        }
    
    };

};

#endif

