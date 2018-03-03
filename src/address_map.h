
// Longest-prefix IP address matching.
//
// This header provides a template class address_map<A, T> which
// is used to map addresses of type A to values of type T.  Address masks
// are used, so that an address of value 1.2.9.12 will match a key of
// 1.2.0.0/16.  The longest prefix i.e. most specific address always matches
// first.
//
// The only requirement on A is that it supports the '&' operation so that
// it provides operator&(unsigned int mask) such that for an address of type
// A, and an unsigned integer value m, A&m returns an address of type
// A containing only the first m bits of the address.  All other bits are zered.

// e.g.
//   tcpip::ip4_address addr1("15.12.8.1");
//   tcpip::ip4_address addr2 = addr1 & 16;
//   std::string str;
//   addr2.to_string(str);
//   assert(str == "15.12.0.0");
//

#include <map>
#include <iostream>

#ifndef ADDRESS_MAP_H
#define ADDRESS_MAP_H

template <class A, class T>
class address_map {

private:
public:
    typedef std::map<A,T> single_map;
    typedef std::map<unsigned int,single_map> mask_map;
    typedef typename std::map<unsigned int,single_map>::const_reverse_iterator
	iter;
    mask_map m;

public:

    // Adds a key to the map, address 'a', mask 'mask', value 't'.
    void insert(const A& a, unsigned int mask, T t) {
	m[mask][a & mask] = t;
    }

    // Removes a key from the map, address 'a', mask 'mark'.
    void remove(A a, unsigned int mask) {
	m[mask].erase(a & mask);
    }

    // Searches the map for address 'a'.  If it exists, returns true and
    // a pointer to the value is returned in 't'.  Otherwise, returns false,
    // and t is undefined.  The hit key is returned as 'hit'.
    bool get(const A& a, T*& t, const A*& hit) {
      
	typename mask_map::reverse_iterator it;

	for(it = m.rbegin(); it != m.rend(); it++) {

	    typename std::map<A, T>::iterator it2;

	    unsigned int mask = it->first;

	    A th = a & mask;
	    std::string th2;
	    a.to_string(th2);
	    th.to_string(th2);

	    it2 = it->second.find(a & mask);

	    if (it2 != it->second.end()) {
		t = &it2->second;
		hit = &it2->first;
		return true;
	    }
	    
	}

	return false;

    }

    // Searches the map for address 'a'.  If it exists, returns true and
    // a pointer to the value is returned in 't'.  Otherwise, returns false,
    // and t is undefined.
    bool get(const A& a, T*& t) {
	const A* ignored = 0;
	return get(a, t, ignored);
    }
      
};

#endif

