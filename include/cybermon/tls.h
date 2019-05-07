
#ifndef CYBERMON_TLS_H
#define CYBERMON_TLS_H

#include <cybermon/context.h>
#include <cybermon/manager.h>
#include <cybermon/pdu.h>

namespace cybermon {

class tls_context : public context {
public:
  tls_context(manager& mgr);
  tls_context(manager& mngr,
              const flow_address& fAddr,
              context_ptr ctxPtr);

  virtual std::string get_type();

  typedef boost::shared_ptr<tls_context> ptr;

	static context_ptr create(manager& m, const flow_address& f,
				  context_ptr par) {
	    context_ptr cp = context_ptr(new tls_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
		context_ptr cp = context::get_or_create(base, f,
		                   tls_context::create);
		ptr sp = boost::dynamic_pointer_cast<tls_context>(cp);
		return sp;
	}

  // buffer for if messages are split over packets/segments
  pdu buffer;
};

class tls {
public:
  static void process(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice);

private:
  struct tls_header {
    uint8_t contentType;
    uint8_t majorVersion;
    uint8_t minorVersion;
    // this is a bit weird, but using a uint16 gives the wrong bytes (presumably due to padding)
    // so use 2 uint8s and join them
    uint8_t length1;
    uint8_t length2;
  };
  static const tls_header* verifyHeader(const pdu_slice& pduSlice);
  static void survey(manager& mgr, context_ptr ctx, const pdu_slice& pduSlice, const tls_header* hdr);
};

} // namespace cybermon

#endif
