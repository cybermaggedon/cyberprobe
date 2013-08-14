
/****************************************************************************

****************************************************************************
*** OVERVIEW
****************************************************************************

Simple monitor.  Takes ETSI streams from cyberprobe, and reports on various
occurances.

Usage:

    cyberprobe <port-number>

****************************************************************************/

#include <iostream>
#include <iomanip>
#include <map>

#include "analyser.h"
#include "monitor.h"
#include "etsi_li.h"
#include "thread.h"
#include "packet_capture.h"
#include "flow.h"
#include "hexdump.h"
#include "context.h"

// Lua
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

// A hideous thing to allow me to pass things between C++ and lua
class hideous {
public:
    analyser::engine* an;
    analyser::context_ptr ctxt;
    analyser::pdu_iter s;
    analyser::pdu_iter e;
    std::string liid;
    analyser::address trigger;
};

void initialise_lua(lua_State*& L)
{
    L = luaL_newstate();
    luaL_openlibs(L);
}

static int cybermon_describe_src(lua_State* L)
{
    std::ostringstream buf;

    void* ud = lua_touserdata(L, -1);
    hideous* h = reinterpret_cast<hideous*>(ud);

    analyser::engine::describe_src(h->ctxt, buf);

    // Pop user-data argument
    lua_pop(L, 1);

    lua_pushstring(L, buf.str().c_str());

    return 1;
}

static int cybermon_describe_dest(lua_State* L)
{
    std::ostringstream buf;

    void* ud = lua_touserdata(L, -1);
    hideous* h = reinterpret_cast<hideous*>(ud);

    analyser::engine::describe_dest(h->ctxt, buf);

    // Pop user-data argument
    lua_pop(L, 1);

    lua_pushstring(L, buf.str().c_str());

    return 1;

}

static int cybermon_get_liid(lua_State* L)
{
    void* ud = lua_touserdata(L, -1);
    hideous* h = reinterpret_cast<hideous*>(ud);

    // Pop user-data argument
    lua_pop(L, 1);

    // Put LIID on stack
    lua_pushstring(L, h->liid.c_str());
    return 1;
}

static int cybermon_get_context_id(lua_State* L)
{
    void* ud = lua_touserdata(L, -1);
    hideous* h = reinterpret_cast<hideous*>(ud);

    // Pop user-data argument
    lua_pop(L, 1);

    // Put LIID on stack
    lua_pushinteger(L, h->ctxt->get_id());
    return 1;
}

static const luaL_reg cybermon_fns[] = {
    {"describe_src", cybermon_describe_src},
    {"describe_dest", cybermon_describe_dest},
    {"get_liid", cybermon_get_liid},
    {"get_context_id", cybermon_get_context_id},
   {NULL, NULL}
};

void initialise_lua_interface(lua_State* L, const std::string& cfg)
{

    luaL_register(L, "cybermon", cybermon_fns);

    if (luaL_dofile(L, cfg.c_str()) != 0) {
	printf("Error running script: %s\n", lua_tostring(L, -1));
	exit(0);
    }

    // Set global 'config'.
    lua_setfield(L, LUA_GLOBALSINDEX, "config");

}


// My observation engine.  Uses the analyser engine, takes the data
// events and keep tabs on how much data has flowed out to attackers.
class obs : public analyser::engine {
private:
    lua_State* lua;

public:

    obs(lua_State* l) : lua(l) {}

    // Map of network address to the amount of data acquired.
    std::map<analyser::address, uint64_t> amounts;

    // Stores the next 'reporting' event for data acquisition by an attacker.
    std::map<analyser::address, uint64_t> next;

    // Observation method.
    void data(const analyser::context_ptr f, analyser::pdu_iter s, 
	      analyser::pdu_iter e);

    // Trigger
    void trigger(const std::string& liid, const tcpip::address& a);

};

void obs::trigger(const std::string& liid, const tcpip::address& a)
{

    // Get information stored about the attacker.
    std::string ta;
    a.to_string(ta);

    // Get observer.data
    lua_getfield(lua, LUA_GLOBALSINDEX, "config");
    lua_getfield(lua, -1, "trigger");

    // Put liid on stack
    lua_pushstring(lua, liid.c_str());
    lua_pushstring(lua, ta.c_str());

    // observer.data(context, data)
    lua_call(lua, 2, 0);

    // Still got 'observer' left on stack, it can go.
    lua_pop(lua, 1);    

}

// Data method.  Keeps track of data flowing to an attacker and reports.
void obs::data(const analyser::context_ptr f, analyser::pdu_iter s, 
	       analyser::pdu_iter e)
{

    // Get information stored about the attacker.
    std::string liid;
    analyser::address trigger_address;
    get_root_info(f, liid, trigger_address);

    hideous h;

    h.an = this;
    h.ctxt = f;
    h.s = s;
    h.e = e;
    h.liid = liid;
    h.trigger = trigger_address;

    // Get network addresses.
    analyser::address src, dest;
    get_network_info(f, src, dest);

    // Get observer.data
    lua_getfield(lua, LUA_GLOBALSINDEX, "config");
    lua_getfield(lua, -1, "data");

    // Put hideous on the stack
    lua_pushlightuserdata(lua, &h);

    // Put data on stack.
    unsigned char buf[e - s];
    std::copy(s, e, buf);
    lua_pushlstring(lua, (char*) buf, e - s);

    // observer.data(context, data)
    lua_call(lua, 2, 0);

    // Still got 'observer' left on stack, it can go.
    lua_pop(lua, 1);

}

// Monitor class, implements the monitor interface to receive data.
class cybermon : public monitor {
private:

    // Analysis engine
    analyser::engine& an;

public:

    // Short-hand for vector iterator.
    typedef std::vector<unsigned char>::iterator iter;

    // Constructor.
    cybermon(analyser::engine& an) : an(an) {}

    // Called when a PDU is received.
    virtual void operator()(const std::string& liid, const iter& s, 
			    const iter& e);

    // Called when attacker is discovered.
    void discovered(const std::string& liid, const tcpip::address& addr);
    
};



// Called when attacker is discovered.
void cybermon::discovered(const std::string& liid,
			  const tcpip::address& addr)
{
    an.discovered(liid, addr);
}

// Called when a PDU is received.
void cybermon::operator()(const std::string& liid, 
			  const iter& s, 
			  const iter& e)
{

    // Get the root context.
//    analyser::context_ptr c = an.get_root_context(liid);

    try {

	// Process the PDU
//	an.process(c, s, e);
	an.process(liid, s, e);

    } catch (std::exception& e) {

	// Processing failure event.
	std::cerr << "Packet failed: " << e.what() << std::endl;

    }

}

int main(int argc, char** argv)
{

    if (argc != 3) {
	std::cerr << "Usage:" << "\tcybermon <port> <config>" << std::endl;
	return 0;
    }

    // Convert port argument to integer.
    std::istringstream buf(argv[1]);
    int port;
    buf >> port;

    // Get config file (Lua).
    std::string config = argv[2];

    lua_State* L;
    initialise_lua(L);
    initialise_lua_interface(L, config);

    // Create the observer instance.
    obs an(L);

    // Create the monitor instance, receives ETSI events, and processes
    // data.
    cybermon m(an);

    // Start an ETSI receiver.
    etsi_li::receiver r(port, m);
    r.start();

    // Wait forever.
    r.join();

    lua_close(L);

}

