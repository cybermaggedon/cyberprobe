
#ifndef CYBERMON_GRE_H
#define CYBERMON_GRE_H

#include "context.h"
#include "observer.h"

namespace cybermon {

// GRE context.  No address information, just flagging the presence of
// GRE.
class gre_context : public context {
public:
  gre_context(manager& mngr);
  gre_context(manager& mngr,
              const flow_address& fAddr,
              context_ptr ctxPtr);

	virtual std::string get_type();

	typedef std::shared_ptr<gre_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new gre_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
		context_ptr cp = context::get_or_create(base, f,
		                   gre_context::create);
		ptr sp = std::dynamic_pointer_cast<gre_context>(cp);
		return sp;
	}
};

class gre {
public:

	// GRE processing function.
	static void process(manager& mgr, context_ptr c, const pdu_slice& s);
private:
  struct gre_header {
    uint8_t flags;
    uint8_t version;
    uint16_t nextProto;
  };
  struct pptp_header {
    uint8_t flags;
    uint8_t version;
    uint16_t nextProto;
    uint16_t keyPayloadLength;
    uint16_t keyCallID;
  };
  static void process_gre(manager& mgr, context_ptr c, const pdu_slice& s, const gre_header* hdr);
  static void process_pptp(manager& mgr, context_ptr c, const pdu_slice& s, const gre_header* hdr);
  static std::string get_next_proto(const gre_header* hdr);
};

} // namespace cybermon

#endif
