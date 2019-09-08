
#include <cyberprobe/protocol/tls_utils.h>
#include <cyberprobe/protocol/tls_exception.h>

using namespace cyberprobe::protocol;

std::string tls_utils::convertTLSVersion(uint8_t maj, uint8_t min)
{
    // should always be true
    if (maj == 3)
        {
            if (min == 0)
                {
                    return "SSL 3.0";
                }
            else if (min < 5)
                {
                    return "TLS 1." + std::to_string(min - 1);
                }
        }
    throw tls_exception("Invalid TLS Version");
}
