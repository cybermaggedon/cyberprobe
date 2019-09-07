#include <vector>
#include <iostream>
#include <sstream>
#include <cassert>
#include <random>
#include <algorithm>
#include <iomanip>
#include <string>

class uuid {
public:
    std::vector<unsigned char> raw;
    std::string to_string() {
	assert(raw.size() == 16);
	std::ostringstream buf;
	buf << std::hex;
	for(int i = 0; i < 16; i++) {
	    buf << std::setfill('0') << std::setw(2) << (int) raw[i];
	    if (i == 3 || i == 5 || i == 7 || i == 9)
		buf << '-';
	}

	return buf.str();
    }
};

class uuid_generator {
    std::random_device device;
    std::mt19937 rand;
    std::uniform_int_distribution<> dist;
public:
    uuid_generator() : rand(device()), dist(0, 255) {}
    unsigned char get() {
	return static_cast<unsigned char>(dist(rand));
    }
    uuid generate() {
	uuid u;
	for(int i = 0; i < 16; i++)
	    u.raw.push_back(get());
	return u;
    }
};

