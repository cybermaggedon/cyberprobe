
////////////////////////////////////////////////////////////////////////////
//
// TLS exceptions.
//
////////////////////////////////////////////////////////////////////////////

#ifndef TLS_EXCEPTION_H
#define TLS_EXCEPTION_H

#include <cybermon/exception.h>

namespace cybermon {

// A tls processing exception
    class tls_exception : public exception {
    public:
        tls_exception(const std::string& m) : exception(m) {}
    };

}

#endif
