
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

#include "engine.h"

namespace cybermon {

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
	    
	    luaL_reg cfns[fns.size() + 1];
	    
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
	    
	    // FIXME: Is this going to get deprecated in LUA 5.2?
	    luaL_register(lua, name.c_str(), cfns);
	    
	}

	// Registers into a metatable.
	void register_table(const std::map<std::string,lua_CFunction>& fns) {
	    
	    luaL_reg cfns[fns.size() + 1];
	    
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
	    
	    luaL_register(lua, 0, cfns);
	    
	}

	// Create table on the stack, pre-allocating items.
	void create_table(int arr, int narr) {
	    lua_createtable(lua, arr, narr);
	}

	// Set table value.
	void set_table(int pos) {
	    lua_settable(lua, pos);
	}

	// Pop p items from the stack.
	void pop(int p = 1) { lua_pop(lua, p); }
		
	// Push nil onto the stack.
	void push() { 
	    lua_pushnil(lua);
	}
	
	// Push a string onto the stack.
	void push(const std::string& s) { 
	    lua_pushlstring(lua, s.c_str(), s.size());
	}

	void push_value(int pos) {
	    lua_pushvalue(lua, pos);
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

	    int ret = lua_pcall(lua, args, res, 0);
	    if (ret == 0)
		return;

	    std::string errmsg;
	    to_string(-1, errmsg);

	    // Pop error message.
	    pop();

	    std::cerr << "LUA error: " << errmsg << std::endl;

	    throw exception(errmsg);

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

	// Get a field from a table, value goes onto the stack.
	void get_table(int pos) {
	    lua_gettable(lua, pos);
	}

	// Push a light userdata value onto the stack.
	void push_light_userdata(void* val) {
	    lua_pushlightuserdata(lua, val);
	}

	void to_string(int pos, std::string& s) {
	    size_t len = 0;
	    const char* c = lua_tolstring(lua, pos, &len);
	    if (c == 0)
		throw std::runtime_error("Not a LUA string.");
	    s.assign(c, len);
	}

	void to_string(int pos, std::vector<unsigned char>& s) {
	    size_t len = 0;
	    const char* c = lua_tolstring(lua, pos, &len);
	    if (c == 0)
		throw std::runtime_error("Not a LUA string.");
	    s.clear();
	    std::back_insert_iterator<pdu> bk = back_inserter(s);
	    std::copy(c, c + len, bk);
	}

	void to_integer(int pos, uint64_t& val) {
	    val = lua_tointeger(lua, pos);
	}

	void to_integer(int pos, uint32_t& val) {
	    val = lua_tointeger(lua, pos);
	}

	void to_integer(int pos, uint16_t& val) {
	    val = lua_tointeger(lua, pos);
	}

	void to_integer(int pos, uint8_t& val) {
	    val = lua_tointeger(lua, pos);
	}

	void to_userdata(int pos, void*& val) {
	    val = lua_touserdata(lua, pos);
	    if (val == 0)
		throw std::runtime_error("Not a LUA userdata.");
	}

	int obj_len(int pos) {
	    return lua_objlen(lua, pos);
	}

	bool is_nil(int pos) {
	    return (lua_isnil(lua, pos) == 1);
	}

	void new_meta_table(const std::string& name) {
	    luaL_newmetatable(lua, name.c_str());
	}

	void* new_userdata(int size) {
	    return lua_newuserdata(lua, size);
	}

	void get_meta_table(const std::string& name) {
	    luaL_getmetatable(lua, name.c_str());
	}

	void set_meta_table(int pos) {
	    lua_setmetatable(lua, pos);
	}

	void push_c_function(lua_CFunction f) {
	    lua_pushcfunction(lua, f);
	}

    };

    class cybermon_lua;

    // We need to pass some values into LUA, so we pass one of these
    // objects as light userdata.  It allows callbacks back into this
    // code to elaborate contexts etc.  This seems the best way to do
    // it because, passing context_ptrs around doesn't work - they're
    // shared ptrs, which don't pass through C very well.
    class context_userdata {
    public:

	// Context
	context_ptr ctxt;

	// Cybermon bridge.
	cybermon_lua* cml;

    };

    // Cybermon wrapper around the LUA state, acts as the cybermon to LUA
    // bridge.
    class cybermon_lua : public lua_state {

    public:

	// These are 'C' functions which get called from lua.
	static int context_describe_src(lua_State*);
	static int context_describe_dest(lua_State*);
	static int context_get_liid(lua_State*);
	static int context_get_id(lua_State*);
	static int context_get_network_info(lua_State*);
	static int context_get_trigger_info(lua_State*);
    	static int context_get_type(lua_State*);
    	static int context_get_reverse(lua_State*);
    	static int context_get_parent(lua_State*);

	static int context_forge_dns_response(lua_State*);
	static int context_forge_tcp_reset(lua_State*);
	static int context_forge_tcp_data(lua_State*);

	static int context_get_src_addr(lua_State*);
	static int context_get_dest_addr(lua_State*);


	static int context_gc(lua_State*);

	// Constructor.
	cybermon_lua(const std::string& cfg);

	using lua_state::push;

	// Push a cybermon context onto the LUA stack as light userdata.
	void push(context_userdata& c) {
	    push_light_userdata(&c);
	}

	void push(context_ptr c);

	// Push DNS stuff.
	void push(const dns_header&);
	void push(const dns_query&);
	void push(const std::list<dns_query>&);
	void push(const dns_rr&);
	void push(const std::list<dns_rr>&);

	void to_dns_header(int pos, dns_header&);

	void to_dns_query(int pos, dns_query&);
	void to_dns_queries(int pos, std::list<dns_query>&);

	void to_dns_rr(int pos, dns_rr&);
	void to_dns_rrs(int pos, std::list<dns_rr>&);

	// Call the config.trigger_up function as trigger_up(liid, addr)
	void trigger_up(const std::string& liid, const tcpip::address& a);

	// Call the config.trigger_down function as trigger_down(liid)
	void trigger_down(const std::string& liid);

	void connection_up(engine& an, context_ptr f);

	void connection_down(engine& an, const context_ptr f);

	// Calls the config.data function as data(context, data).
	// The 'context' variable passed to LUA is a light userdata pointer,
	// allowing calling back into the C++ code.  The value is only valid
	// in LUA space for the duration of this call.
	void unrecognised_stream(engine& an, const context_ptr f, 
				 pdu_iter s, pdu_iter e);

	void unrecognised_datagram(engine& an, const context_ptr f, 
				   pdu_iter s, pdu_iter e);

	void icmp(engine& an, const context_ptr f, 
		  pdu_iter s, pdu_iter e);

	typedef std::map<std::string,std::pair<std::string,std::string> > 
	    http_header;

	void http_request(engine& an, const context_ptr cf,
			  const std::string& method,
			  const std::string& url,
			  const http_header& hdr,
			  pdu_iter body_start,
			  pdu_iter body_end);

	void http_response(engine& an, const context_ptr cf,
			   unsigned int code,
			   const std::string& status,
			   const http_header& hdr,
			   const std::string& url,
			   pdu_iter body_start,
			   pdu_iter body_end);

	void dns_message(engine& an, const context_ptr cf,
			 const dns_header& hdr, 
			 const std::list<dns_query> queries,
			 const std::list<dns_rr> answers,
			 const std::list<dns_rr> authorities,
			 const std::list<dns_rr> additional);

    };

};

