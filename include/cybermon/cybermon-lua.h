
////////////////////////////////////////////////////////////////////////////
//
// Cybermon-LUA interface.  LUA bridge, allows passing information between
// Cybermon C++ code and the LUA configuration code.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_CYBERMON_LUA_H
#define CYBERMON_CYBERMON_LUA_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

// Lua
extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#include <libgen.h>
#include <string.h>

#include <string>
#include <stdexcept>
#include <map>

#include "engine.h"
#include <cybermon/tls_handshake_protocol.h>

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
	virtual ~lua_state() {
	    lua_close(lua);
	}

	// Add module's parent directory to LUA's package.path, which allows
	// this module to 
	void add_parent_directory_path(const std::string& path) {

	    // When loading a configuration file, this allows adding that
	    // configuration file's parent directory to Lua package.path,
	    // which allows the configuration file to require() other modules
	    // without having to worry about where they are.

	    // Create space for the config filename.
	    char tmp[path.size() + 1];

	    // Take a copy, as a C-string.
	    memcpy(tmp, path.c_str(), path.size());
	    tmp[path.size()] = 0;

	    // Get directory name of config file.
	    const char* dir = dirname(tmp);

	    // Get package.path.
	    get_global("package");
	    get_field(-1, "path");
	    std::string pkg_path;
	    to_string(-1, pkg_path);
	    pop(); // Pop return string
	    // 'package' still on stack.

	    // Append the config file's directory to the package path string.
	    pkg_path += ";";
	    pkg_path += dir;
	    pkg_path += "/?.lua";

	    // 'package' is still on stack.

	    // Set package.path to this value.
	    push("path");
	    push(pkg_path);
	    set_table(-3);

	    // Pop package, stack is as it was.
	    pop(); // package

	}

	// Loads a module.  If the module uses 'return' to pass back its
	// compiled code, this will be on the stack.
	void load_module(const std::string& path) {

	    // Load config file.
	    if (luaL_dofile(lua, path.c_str()) != 0) {
		std::string err;
		err = "Error running script: ";
		err += lua_tostring(lua, -1);
		throw exception(err);
	    }
	    
	}
	
	// Registers a module which consists of 'C' functions.
	void register_module(const std::string& name,
			     const std::map<std::string,lua_CFunction>& fns) {
	    
#ifdef HAVE_LUAL_SETFUNCS
	    // LUA 5.2 and on
	    luaL_Reg cfns[fns.size() + 1];
#else
	    // LUA 5.1
	    luaL_reg cfns[fns.size() + 1];
#endif

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
	    
#ifdef HAVE_LUAL_SETFUNCS
	    // LUA 5.2 and on
	    luaL_setfuncs(lua, cfns, 0);
	    set_global(name.c_str());
#else
	    // LUA 5.1
	    luaL_register(lua, name.c_str(), cfns);
#endif
	    
	}

	// Registers into a metatable.
	void register_table(const std::map<std::string,lua_CFunction>& fns);

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
	
	// Push an integer onto the stack.
	void push(int num) { 
	    lua_pushinteger(lua, num);
	}
	
	// Push an integer onto the stack.
	void push(long num) { 
	    lua_pushinteger(lua, num);
	}
		
	// Push an integer onto the stack.
	void push(unsigned int num) { 
	    lua_pushinteger(lua, num);
	}
		
	// Push an integer onto the stack.
	void push(unsigned long num) { 
	    lua_pushinteger(lua, num);
	}
	
	// Push a float onto the stack.
	void push(double num) { 
	    lua_pushnumber(lua, num);
	}
	
	// Push a boolean onto the stack.
	void push_bool(bool b) { 
	    lua_pushboolean(lua, b);
	}

	// // Push a string (defined by iterators).
	// void push(std::vector<unsigned char>::const_iterator s,
	// 	  std::vector<unsigned char>::const_iterator e) {
	//     // FIXME: Lot of copying?
	//     unsigned char* buf = new unsigned char[e - s];
	//     std::copy(s, e, buf);
	//     lua_pushlstring(lua, (char*) buf, e - s);
	//     delete[] buf;
	// }

	// Push a string (defined by iterators).
	template < class Iter >
	void push(Iter s, Iter e) {
	    lua_pushlstring(lua, reinterpret_cast<const char*>(&(*s)), e - s);
	}


/*	void push(int size, unsigned char* buf ) {
	    // FIXME: Lot of copying?
	    //unsigned char* buf = new unsigned char[e - s];
	    //std::copy(s, e, buf);
	    lua_pushlstring(lua, (char*) buf, size);
	    delete[] buf;
	}*/

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
		throw std::invalid_argument("Not a LUA string.");
	    s.assign(c, len);
	}

	void to_string(int pos, std::vector<unsigned char>& s) {
	    size_t len = 0;
	    const char* c = lua_tolstring(lua, pos, &len);
	    if (c == 0)
		throw std::invalid_argument("Not a LUA string.");
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

	void to_double(int pos, double& val) {
	    val = lua_tonumber(lua, pos);
	}

	void to_userdata(int pos, void*& val) {
	    val = lua_touserdata(lua, pos);
	    if (val == 0)
		throw std::invalid_argument("Not a LUA userdata.");
	}

	int raw_len(int pos) {
#ifdef HAVE_LUA_RAWLEN
	    return lua_rawlen(lua, pos);
#else
	    return lua_objlen(lua, pos);
#endif
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

	static int context_get_creation_time(lua_State*);

	static int context_get_direction(lua_State*);

	static int context_gc(lua_State*);

	// Constructor.
	cybermon_lua(const std::string& cfg);

	using lua_state::push;

	// Push a cybermon context onto the LUA stack as light userdata.
	void push(context_userdata& c) {
	    push_light_userdata(&c);
	}

	// Push a context pointer
	void push(context_ptr c);

	// Push a timestamp value (convert to time).
	void push(const timeval& time);

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
	
	// Push NTP stuff
	void push(const ntp_hdr&);
	void push(const ntp_timestamp&);
	void push(const ntp_control&);
	void push(const ntp_private&);

	// Call the config.trigger_up function as trigger_up(liid, addr)
	//void trigger_up(const std::string& liid, const tcpip::address& a);
	void trigger_up(const std::string& liid, const std::string& a,
			const timeval& time);

	// Call the config.trigger_down function as trigger_down(liid)
	void trigger_down(const std::string& liid, const timeval& time);

	void connection_up(engine& an, context_ptr f, const timeval& time);

	void connection_down(engine& an, const context_ptr f,
			     const timeval& time);

	// Calls the config.data function as data(context, data).
	// The 'context' variable passed to LUA is a light userdata pointer,
	// allowing calling back into the C++ code.  The value is only valid
	// in LUA space for the duration of this call.
	void unrecognised_stream(engine& an, const context_ptr f, 
				 pdu_iter s, pdu_iter e,
				 const timeval& time, int64_t posn);

	void unrecognised_datagram(engine& an, const context_ptr f, 
				   pdu_iter s, pdu_iter e, const timeval& time);

	void icmp(engine& an, const context_ptr f,
		  unsigned int type,
		  unsigned int code,
		  pdu_iter s,
		  pdu_iter e,
		  const timeval& time);

	void imap(engine& an,
		  const context_ptr f,
		  pdu_iter s,
		  pdu_iter e,
		  const timeval& time);

	void imap_ssl(engine& an,
		      const context_ptr f,
		      pdu_iter s,
		      pdu_iter e,
		      const timeval& time);
	
	void pop3(engine& an,
		  const context_ptr f,
		  pdu_iter s,
		  pdu_iter e,
		  const timeval& time);
	
	void pop3_ssl(engine& an,
		      const context_ptr f,
		      pdu_iter s,
		      pdu_iter e,
		      const timeval& time);
	
	void rtp(engine& an,
		 const context_ptr f,
		 pdu_iter s,
		 pdu_iter e,
		 const timeval& time);
	
	void rtp_ssl(engine& an,
		     const context_ptr f,
		     pdu_iter s,
		     pdu_iter e,
		     const timeval& time);
	
	void sip_request(engine& an,
			 const context_ptr f,
			 const std::string& method,
			 const std::string& from,
			 const std::string& to,
			 pdu_iter s,
			 pdu_iter e,
			 const timeval& time);
	
	void sip_response(engine& an,
			  const context_ptr f,
			  unsigned int code,
			  const std::string& status,
			  const std::string& from,
			  const std::string& to,
			  pdu_iter s,
			  pdu_iter e,
			  const timeval& time);
	
	void sip_ssl(engine& an,
		     const context_ptr f,
		     pdu_iter s,
		     pdu_iter e,
		     const timeval& time);
	
	void smtp_auth(engine& an,
		       const context_ptr f,
		       pdu_iter s,
		       pdu_iter e,
		       const timeval& time);

	typedef std::map<std::string,std::pair<std::string,std::string> > 
	    http_header;

	void http_request(engine& an, const context_ptr cf,
			  const std::string& method,
			  const std::string& url,
			  const http_header& hdr,
			  pdu_iter body_start,
			  pdu_iter body_end,
			  const timeval& time);
    
	void http_response(engine& an, const context_ptr cf,
			   unsigned int code,
			   const std::string& status,
			   const http_header& hdr,
			   const std::string& url,
			   pdu_iter body_start,
			   pdu_iter body_end,
			   const timeval& time);

	void smtp_command(engine& an, const context_ptr cf,
			  const std::string& command,
			  const timeval& time);

	void smtp_response(engine& an, const context_ptr cf,
			   int status,
			   const std::list<std::string>& text,
			   const timeval& time);

	void smtp_data(engine& an, const context_ptr cf,
		       const std::string& from,
		       const std::list<std::string>& to,
		       pdu_iter s,
		       pdu_iter e,
		       const timeval& time);

	void ftp_command(engine& an, const context_ptr cf,
			 const std::string& command,
			 const timeval& time);

	void ftp_response(engine& an, const context_ptr cf,
			  int status,
			  const std::list<std::string>& responses,
			  const timeval& time);

	void dns_message(engine& an,
			 const context_ptr cf,
			 const dns_header& hdr, 
			 const std::list<dns_query> queries,
			 const std::list<dns_rr> answers,
			 const std::list<dns_rr> authorities,
			 const std::list<dns_rr> additional,
			 const timeval& time);

	void ntp_timestamp_message(engine& an, const context_ptr cf,
				   const ntp_timestamp& ts,
				   const timeval& time);
			                  
	void ntp_control_message(engine& an, const context_ptr cf,
				 const ntp_control& ctrl, const timeval& time);
			                 
	void ntp_private_message(engine& an, const context_ptr cf,
				 const ntp_private& priv, const timeval& time);
	
	void gre_message(engine& an,
  			 const context_ptr cf,
         const std::string& nextProto,
         const uint32_t key,
         const uint32_t sequenceNo,
         pdu_iter payload_start,
         pdu_iter payload_end,
         const timeval& time);

	void gre_pptp_message(engine& an,
  			 const context_ptr cf,
         const std::string& nextProto,
         const uint16_t payload_length,
         const uint16_t call_id,
         const uint32_t sequenceNo,
         const uint32_t ackNo,
         pdu_iter payload_start,
         pdu_iter payload_end,
         const timeval& time);

	void esp(engine& an,
  			 const context_ptr cf,
  			 const uint32_t spi,
  			 const uint32_t sequence,
  			 const uint32_t length,
  			 pdu_iter start,
  			 pdu_iter end,
  			 const timeval& time);

	void unrecognised_ip_protocol(engine& an,
  			 const context_ptr cf,
  			 const uint8_t nxtProto,
  			 const uint32_t len,
  			 pdu_iter start,
  			 pdu_iter end,
  			 const timeval& time);

	void wlan(engine& an,
  			 const context_ptr cf,
  			 const uint8_t version,
  			 const uint8_t type,
  			 const uint8_t subtype,
  			 const uint8_t flags,
  			 const bool is_protected,
  			 const uint16_t duration,
  			 const std::string& filt_addr,
  			 const uint8_t frag_num,
  			 const uint16_t seq_num,
  			 const timeval& time);

	void tls(engine& an,
   			 const context_ptr cf,
   			 const std::string& version,
   			 const uint8_t contentType,
   			 const uint16_t length,
   			 const timeval& time);

	void tls_client_hello(engine& an,
    			 const context_ptr cf,
    			 const tls_handshake_protocol::client_hello_data& data,
    			 const timeval& time);

	void tls_server_hello(engine& an,
     			 const context_ptr cf,
     			 const tls_handshake_protocol::server_hello_data& data,
     			 const timeval& time);

	void tls_certificates(engine& an,
      			 const context_ptr cf,
      			 const std::vector<std::vector<uint8_t>>& certs,
      			 const timeval& time);

	void tls_server_key_exchange(engine& an,
       			 const context_ptr cf,
       			 const tls_handshake_protocol::key_exchange_data& data,
       			 const timeval& time);

	void tls_server_hello_done(engine& an,
        			 const context_ptr cf,
        			 const timeval& time);

    };

};

#endif
