
#ifndef CYBERMON_802_11_H
#define CYBERMON_802_11_H

#include "context.h"
#include "observer.h"

namespace cybermon {

// 802.11 context.  No address information, just flagging the presence of
// 802.11.
class wlan_context : public context {
public:
  wlan_context(manager& mngr);
  wlan_context(manager& mngr,
              const flow_address& fAddr,
              context_ptr ctxPtr);

	virtual std::string get_type();

	typedef std::shared_ptr<wlan_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new wlan_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
		context_ptr cp = context::get_or_create(base, f,
		                   wlan_context::create);
		ptr sp = std::dynamic_pointer_cast<wlan_context>(cp);
		return sp;
	}
};

class wlan {
public:

	// 802.11 processing function.
	static void process(manager& mgr, context_ptr c, const pdu_slice& s);
private:
  struct wlan_header {
    uint16_t frame_controls;
    uint16_t duration;
    uint8_t rx[6];
    uint8_t tx[6];
    uint8_t filt[6];
    uint16_t seq_control;

  };
};

} // namespace cybermon

#endif
