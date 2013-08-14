
////////////////////////////////////////////////////////////////////////////
//
// Cybermon-LUA interface.  LUA bridge, allows passing information between
// Cybermon C++ code and the LUA configuration code.
//
////////////////////////////////////////////////////////////////////////////

// Lua
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include <string>
#include <stdexcept>
#include <map>

#include "analyser.h"

// Generic C++ wrapper around LUA.
class lua_state {
protected:

    // LUA state.
    lua_State* lua;

public:

    // Constructor.
    lua_state() {
	lua = luaL_newstate();
	luaL_openlibs(lua);
    }

    // Destructor.
    ~lua_state() {
	lua_close(lua);
    }

    // Loads a module.  If the module uses 'return' to pass back its
    // compiled code, this will be on the stack.
    void load_module(const std::string& path) {

	if (luaL_dofile(lua, path.c_str()) != 0) {
	    std::string err;
	    err = "Error running script: ";
	    err += lua_tostring(lua, -1);
	    throw std::runtime_error(err);
	}

    }

    // Registers a module which consists of 'C' functions.
    void register_module(const std::string& name,
			 const std::map<std::string,lua_CFunction>& fns) {

	luaL_reg* cfns = new luaL_reg[fns.size() + 1];

	int pos = 0;
	for(std::map<std::string,lua_CFunction>::const_iterator it = 
		fns.begin();
	    it != fns.end();
	    it++) {
	    cfns[pos].name = it->first.c_str();
	    cfns[pos].func = it->second;
	    pos++;
	}

	cfns[pos].name = 0;
	cfns[pos].func = 0;

	// FIXME: This is marked deprecated.
	luaL_register(lua, name.c_str(), cfns);

    }

    // Pop p items from the stack.
    void pop(int p) { lua_pop(lua, p); }

    // Push a string onto the stack.
    void push(const std::string& s) { 
	lua_pushlstring(lua, s.c_str(), s.size());
    }

    // Push a string onto the stack.
    void push(int num) { 
	lua_pushinteger(lua, num);
    }

    // Push a string (defined by iterators).
    void push(std::vector<unsigned char>::const_iterator s,
	      std::vector<unsigned char>::const_iterator e) {
	unsigned char buf[e - s];
	std::copy(s, e, buf);
	lua_pushlstring(lua, (char*) buf, e - s);
    }

    // Call a function.  args = number of arguments on the stack
    // res = number of return values.
    void call(int args, int res) {
	lua_call(lua, args, res);
    }

    // Get a global variable value onto the stack.
    void get_global(const std::string& name) {
	lua_getglobal(lua, name.c_str());
    }

    // Set a global variable from the stack.
    void set_global(const std::string& name) {
	lua_setglobal(lua, name.c_str());
    }

    // Get a field from a table, value goes onto the stack.
    void get_field(int pos, const std::string& name) {
	lua_getfield(lua, pos, name.c_str());
    }

    // Push a light userdata value onto the stack.
    void push_light_userdata(void* val) {
	lua_pushlightuserdata(lua, val);
    }

};

// This is a bit kludgy.  We need to pass some values into LUA, so we pass
// one of these objects as light userdata.  It allows callbacks back into
// this code to elaborate contexts etc.  This seems the best way to do it
// because, passing context_ptrs around doesn't work - they're shared ptrs,
// which don't pass through C very well.
    class cybermon_lua;
class cybermon_context {
public:

    // Analyser engine.
    analyser::engine* an;

    // Context
    analyser::context_ptr ctxt;

    // Iterators, defining the bounds of the data.
    analyser::pdu_iter s;
    analyser::pdu_iter e;

    // LIID.
    std::string liid;
    
    // Address which triggered processing
    analyser::address trigger;

    // Cybermon bridge.
    cybermon_lua* cml;

};

// Cybermon wrapper around the LUA state, acts as the cybermon to LUA
// bridge.
class cybermon_lua : public lua_state {

public:

    // These are 'C' functions which get called from lua.
    static int describe_src(lua_State*);
    static int describe_dest(lua_State*);
    static int get_liid(lua_State*);
    static int get_context_id(lua_State*);
    
    // The C++ equiv of above.
    void describe_src(cybermon_context* h);
    void describe_dest(cybermon_context* h);
    void get_liid(cybermon_context* h);
    void get_context_id(cybermon_context* h);

    // Constructor.
    cybermon_lua(const std::string& cfg) {
	
	// C functions go in a map.
	std::map<std::string,lua_CFunction> fns;
	fns["describe_src"] = &describe_src;
	fns["describe_dest"] = &describe_src;
	fns["get_liid"] = &get_liid;
	fns["get_context_id"] = &get_context_id;

	// These are registered with lua as the 'cybermon' module.
	register_module("cybermon", fns);

	// Load the configuration file.
	load_module(cfg);

	// Transfer result from module to global variable 'config'.
	set_global("config");

    }

    // Push a cybermon context onto the LUA stack as light userdata.
    void push_cybermon_context(cybermon_context& c) {
	push_light_userdata(&c);
    }

    // Call the config.trigger function as trigger(liid, addr)
    void trigger(const std::string& liid, const tcpip::address& a);

    // Calls the config.data function as data(context, data).
    // The 'context' variable passed to LUA is a light userdata pointer,
    // allowing calling back into the C++ code.  The value is only valid
    // in LUA space for the duration of this call.
    void data(analyser::engine& an, const analyser::context_ptr f, 
	      analyser::pdu_iter s, 
	      analyser::pdu_iter e);

};



