
#ifndef CYBERMON_ESP_H
#define CYBERMON_ESP_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/observer.h>

namespace cyberprobe {
namespace protocol {

// ESP context.  No address information, just flagging the presence of
// ESP.
    class esp_context : public context {
    public:
        esp_context(manager& mngr);
        esp_context(manager& mngr,
                    const flow_address& fAddr,
                    context_ptr ctxPtr);

	virtual std::string get_type();

	typedef std::shared_ptr<esp_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new esp_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
            context_ptr cp = context::get_or_create(base, f,
                                                    esp_context::create);
            ptr sp = std::dynamic_pointer_cast<esp_context>(cp);
            return sp;
	}
    };

    class esp {
    public:

	// ESP processing function.
	static void process(manager& mgr, context_ptr c, const pdu_slice& s);
    private:
        struct esp_header {
            uint32_t spi;
            uint32_t sequence;
        };
    };

}
}

#endif
