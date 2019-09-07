
#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <string>

namespace cyberprobe {

// Interface to an class which knows about parameters.
class parameterised {
public:
    virtual ~parameterised() {}

    // Get the value of a parameter.  If parameter is not known, the
    // default value is returned.
    virtual std::string get_parameter(const std::string& key,
				      const std::string& deflt = "") = 0;
};

};

#endif

