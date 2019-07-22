
#include "interface.h"
#include "json.h"

using json = nlohmann::json;

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

};



