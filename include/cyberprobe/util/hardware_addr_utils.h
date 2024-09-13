
#ifndef HARDWARE_ADDR_UTILS_H
#define HARDWARE_ADDR_UTILS_H

#include <string>
#include <stdint.h>

namespace cyberprobe {
    namespace util {
        namespace hw_addr_utils {

            // no bounds checking, must be done in caller
            std::string to_string(const uint8_t* addr);

        }
    }
}

#endif
