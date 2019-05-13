
////////////////////////////////////////////////////////////////////////////
//
// Analyser exceptions.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_EXCEPTION_H
#define CYBERMON_EXCEPTION_H

#include <stdexcept>

namespace cybermon {

    // A cybermon exception
    class exception : public std::runtime_error {
    public:
        exception(const std::string& m) : std::runtime_error(m) {}
    };

}

#endif
