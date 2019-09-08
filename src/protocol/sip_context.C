
#include <cyberprobe/protocol/sip_context.h>
#include <regex>


using namespace cyberprobe::protocol;

// Constructor.
sip_context::sip_context(manager& m) : context(m) {}

// Constructor, when specifying flow address and parent context.
sip_context::sip_context(manager& m, const flow_address& a, context_ptr p) : context(m) {
    addr = a;
    parent = p; 
}

std::string sip_context::get_type() {
    return "sip";
}

context_ptr sip_context::create(manager& m, const flow_address& f, context_ptr par) {
    context_ptr cp = context_ptr(new sip_context(m, f, par));
    return cp;
}

// Given a flow address, returns the child context.
sip_context::ptr sip_context::get_or_create(context_ptr base, const flow_address& f) {
    context_ptr cp = context::get_or_create(base, f, sip_context::create);
    ptr sp = std::dynamic_pointer_cast<sip_context>(cp);
    return sp;
}

void sip_context::parse(std::string body) {

    from = "<unknown>";
    to   = "<unknown>";

    audio_port = 0;
    video_port = 0;


    std::match_results<std::string::const_iterator> what;

    static const std::regex sip_from("From: .*?(<.*>)");
    if (regex_search(body, what, sip_from, std::regex_constants::match_any))
        {
            from = what[1];
        }

    static const std::regex sip_to("To: .*?(<.*>)");
    if (regex_search(body, what, sip_to, std::regex_constants::match_any))
        {
            to = what[1];
        }

    static const std::regex sip_content_audio("m=audio ([0-9]+) RTP");
    if (regex_search(body, what, sip_content_audio,
		     std::regex_constants::match_any))
        {
            // Convert the port number into an int - nasty!
            std::istringstream buf(what[1]);
            buf >> audio_port;
        }

    static const std::regex sip_content_video("m=video ([0-9]+) RTP");
    if (regex_search(body, what, sip_content_video,
		     std::regex_constants::match_any))
        {
            // Convert the port number into an int - nasty!
            std::istringstream buf(what[1]);
            buf >> video_port;
        }
}


