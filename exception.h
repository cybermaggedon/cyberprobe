
////////////////////////////////////////////////////////////////////////////
//
// Analyser exceptions.
//
////////////////////////////////////////////////////////////////////////////

#ifndef EXCEPTION_H
#define EXCEPTION_H

namespace analyser {

    // An analyser exception
    class exception : public std::runtime_error {
    public:
        exception(const std::string& m) : std::runtime_error(m) {}
    };
    
};

#endif

