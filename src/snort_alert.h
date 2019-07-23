
////////////////////////////////////////////////////////////////////////////
//
// SNORT ALERTER RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef SNORT_ALERT_H
#define SNORT_ALERT_H

#include <cybermon/resource.h>

#include "delivery.h"

namespace snort_alert {

    using json = nlohmann::json;

    // Specification for a snort alerter.
    class spec : public cybermon::specification {

    public:

        // Type is 'snort_alerter'.
        virtual std::string get_type() const { return "snort_alerter"; }

        // Pathname of socket.
        std::string path;

        // Duration for tips to stay active.
        int duration;

        // Constructors.
        spec() {}

        spec(const std::string& path, int duration) {
            this->path = path; this->duration = duration;
        }

        // Hash is path:duration
        virtual std::string get_hash() const;

    };

    // Snort alerter, receives snort alerts and enables targeting on alerted
    // IP addresses.
    class snort_alerter : public cybermon::resource {

    private:

        // Specification.
        spec& sp;

        // True = running.
        bool running;

        // Deliver engine, we mess with the targeting on this.
        delivery& deliv;

        std::thread* thr;

    public:

        // Constructor.
        snort_alerter(spec& sp,
                      delivery& deliv) : sp(sp), deliv(deliv) {
            running = true; 
        }

        // Destructor
        virtual ~snort_alerter() {
            delete thr;
        }

        // Thread body.
        virtual void run();

        // Thread start.
        virtual void start() {

            thr = new std::thread(&snort_alerter::run, this);

            std::cerr << "Start snort alerter on " << sp.path << std::endl;
        }

        // Thread stop.
        virtual void stop() {
            running = false;
            join();
            std::cerr << "Stopped snort alerter." << std::endl;
        }

        virtual void join() {
            thr->join();
        }
    
    };

    void to_json(json& j, const spec& s);

    void from_json(const json& j, spec& s);

};

#endif

