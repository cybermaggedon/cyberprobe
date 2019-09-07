
#include <cyberprobe/probe/interface.h>
#include <cyberprobe/probe/delivery.h>
#include <nlohmann/json.h>

using json = nlohmann::json;

namespace cyberprobe {

namespace probe {

namespace interface {

    void to_json(json& j, const interface::spec& s) {
        j = json{{"interface", s.ifa}, {"filter", s.filter},
                 {"delay", s.delay}};
    }

    void from_json(const json& j, interface::spec& s) {
        j.at("interface").get_to(s.ifa);
        try {
            j.at("filter").get_to(s.filter);
        } catch (...) {
            s.filter = "";
        }
        try {
            j.at("delay").get_to(s.delay);
        } catch (...) {
            s.delay = 0.0;
        }
    }

    std::string spec::get_hash() const {
        json j = *this;
        return j.dump();
    }

    void iface::start() {

        deliv.add_interface(sp);

        std::cerr << "Capture on interface " << sp.ifa << " started."
                  << std::endl;
        if (sp.filter != "")
            std::cerr << "  filter: " << sp.filter << std::endl;
        if (sp.delay != 0.0)
            std::cerr << "  delay: " << sp.delay << std::endl;

    }

    void iface::stop() { 
        deliv.remove_interface(sp);
        std::cerr << "Capture on interface " << sp.ifa << " stopped."
                  << std::endl;
    }
    
}

}

}

