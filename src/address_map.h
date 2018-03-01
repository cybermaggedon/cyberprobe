
#include <map>
#include <iostream>

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

    void insert(const A& a, unsigned int mask, T t) {
	m[mask][a & mask] = t;
    }

    void remove(A a, unsigned int mask) {
	m[mask].erase(a & mask);
    }

    bool get(const A& a, const T*& t) {
      
	typename mask_map::const_reverse_iterator it;

	for(it = m.rbegin(); it != m.rend(); it++) {


	    typename std::map<A, T>::const_iterator it2;

	    unsigned int mask = it->first;

	    A th = a & mask;
	    std::string th2;
	    a.to_string(th2);
	    th.to_string(th2);

	    it2 = it->second.find(a & mask);

	    if (it2 != it->second.end()) {
		t = & it2->second;
		return true;
	    }
	    
	}

	return false;

    }

};

