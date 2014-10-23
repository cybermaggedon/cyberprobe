
#ifndef SERIAL_H
#define SERIAL_H

#include <stdint.h>

template <typename SINT = int32_t, typename UINT = uint32_t>
class serial {

private:
    UINT val;

public:
    serial(UINT val = 0) : val(val) {}
    UINT value() const { return val; }
    SINT distance(UINT cmp) const {
	return SINT(cmp - val);
    }

    bool operator<(UINT cmp) const { return distance(cmp) > 0; }
    bool operator<=(UINT cmp) const { return distance(cmp) >= 0; }
    bool operator>(UINT cmp) const { return distance(cmp) < 0; }
    bool operator>=(UINT cmp) const { return distance(cmp) <= 0; }
    bool operator==(UINT cmp) const { return distance(cmp) == 0; }

    UINT operator=(UINT cmp) { return val = cmp; }

    bool operator<(serial& cmp) const { return distance(cmp.val) > 0; }

    serial operator+(UINT cmp) { return serial(val + cmp); }
    serial& operator+=(UINT cmp) { val += cmp; return *this; }

};

#endif

