
////////////////////////////////////////////////////////////////////////////
//
// Analyser exceptions.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERPROBE_ANALYSER_EXCEPTION_H
#define CYBERPROBE_ANALYSER_EXCEPTION_H

#include <stdexcept>

namespace cyberprobe {

    // A cybermon exception
    class exception : public std::runtime_error {
    public:
        exception(const std::string& m) : std::runtime_error(m) {}
    };

}

#endif

