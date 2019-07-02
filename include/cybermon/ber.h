
#ifndef CYBERMON_BER_H
#define CYBERMON_BER_H

#include <memory>

#include <cybermon/socket.h>

#include <algorithm>
#include <list>
#include <vector>
#include <functional>

namespace cybermon {

/** BER decoding utilities. */
    namespace ber {

        // Conversion between integer and 2's complement byte string.
        template <typename DIGIT = unsigned char, int BITS = 8,
                  typename VALUE = int64_t>
        class integer {
        public:
    
            VALUE value;

            integer(VALUE v) : value(v) {}
            integer() : value(0) {}

            // Convert int into 2‘s complement vector.
            void encode(std::vector<DIGIT>& b) {
                encode(value, b);
            }

            static void encode(VALUE val, std::vector<DIGIT>& b) {

                if (val == 0) {
                    b.push_back(0);
                    return;
                }
	    
                int64_t base = 1 << BITS;
                unsigned int mask = ((1 << BITS) -1 );
                b.clear();
	    
                if (val < 0) {
                    encode(-(val + 1), b);
                    for(typename std::vector<DIGIT>::iterator it = b.begin();
                        it != b.end();
                        it++)
                        *it = (~*it & mask);
                    return;
                }
	    
                while (val != 0) {
                    b.push_back(val % base);
                    val >>= BITS;
                }

                // MSB bit set? That's the sign bit, so need to zero—pad.
                if (b.back() & (1 << (BITS - 1)))
                    b.push_back(0);
	    
            }

            // Convert 2's complement vector into int.
            void decode(const std::vector<DIGIT>& b) {
	    
                value = 0;
	    
                for(typename std::vector<DIGIT>::const_reverse_iterator it =
                        b.rbegin();
                    it != b.rend();
                    it++) {
		
                    value = (value << BITS) + *it;

                    if (it == b.rbegin()) {
                        if (*it & (1 << (BITS - 1))) {
                            value -= (1 << (BITS));
                        }
                    }

                }

            }

        };

        enum tag_class {
            universal = 0, application = 1, context_specific = 2, priv = 3
        };

        /** A BER PDU and its tag number */
        class berpdu {
        public:

            typedef std::vector<unsigned char> pdu;
            typedef std::shared_ptr<pdu> pdu_ptr;

            /** The PDU */
            pdu_ptr data;

            berpdu() {
                is_decoded = false;
                data = pdu_ptr(new pdu);
            }

            tag_class get_class() const {
                int bits = data->at(0) & 0xc0;
                if (bits == 0) return universal;
                if (bits == 0x80) return context_specific;
                if (bits == 0xc0) return priv;
                return application;
            }

            bool is_constructed() const {
                return (data->at(0) & 0x20) == 0x20;
            }

        private:
            std::list<berpdu> contained_pdus;
            bool is_decoded;

        public:
            berpdu& get_element(int tag) {
	    
                if (!is_decoded) {
                    if (!is_constructed()) 
                        throw std::out_of_range("Not a constructed PDU.");
                    contained_pdus.clear();
                    decode_construct(contained_pdus);
                    is_decoded = true;
                }

                for(std::list<berpdu>::iterator it = contained_pdus.begin();
                    it != contained_pdus.end();
                    it++) {
                    if (it->get_tag() == tag)
                        return *it;
                }

                std::ostringstream buf;
                buf << "No PDU with tag " << tag;
                throw std::out_of_range(buf.str());

            }

            long decode_tag(long& pos) const {

                // Low order case.
                if ((data->at(pos) & 0x1f) != 0x1f)
                    return data->at(pos++) & 0x1f;

                pos++;

                long tag = 0;
                while (1) {
                    tag <<= 7;
                    tag |= (data->at(pos) & 0x7f);
                    if (data->at(pos++) & 0x80)
                        return tag;
                } 

            }

            long get_tag() const {
                long pos = 0;
                return decode_tag(pos);
            }

            long content_start() const {
	  
                int pos = 1;

                // Skip the tag.
                if ((data->at(0) & 0x1f) == 0x1f) {
                    while ((data->at(pos) & 0x80) == 0)
                        pos++;
                    pos++;
                }

                // Low order length case.
                if ((data->at(pos) & 0x80) == 0)
                    return pos + 1;

                // Length of the length.
                long b = data->at(pos++) & 0x7f;

                return pos + b;

            }

            long decode_length(long& pos) const {

                // Assuming at start of length.

                // Short form.
                if ((data->at(pos) & 0x80) == 0)
                    return data->at(pos++);

                // Length of the length.
                long b = data->at(pos++) & 0x7f;

                long length = 0;
                while (b-- > 0) {
                    length <<= 8;
                    length |= data->at(pos++);
                }

                return length;

            }

            long get_length() const {

                long pos = 0;

                // Skip the tag.
                decode_tag(pos);

                return decode_length(pos);

            }

            /** BER encoding of the tag value. */
            void encode_tag(tag_class cls, long tag) {

                if (tag < 128) {
                    int cls_bits = cls << 6;
                    data->push_back(cls_bits | tag);
                    return;
                }

                int cls_bits = cls << 6;
                data->push_back(cls_bits | 0x1f);
	    
                // This doesn't deal with the zero case, but that's covered above.

                // Encode tag, base128.  This writes it out in 'reverse' order,
                // cause BER has MSB first.
                std::vector<unsigned char> tbytes;
                while (tag != 0) {
                    tbytes.push_back(tag & 0x7f);
                    tag /= 128;
                }

                // The 'last' byte has flag at 0x80 set.
                // Array is in reverse order at this point.
                tbytes[0] |= 0x80;

                // Put bytes in data, in reverse order.
                std::back_insert_iterator<std::vector<unsigned char> > iter(*data);
                std::copy(tbytes.rbegin(), tbytes.rend(), iter);

            }

            /** BER encoding of the length value. */
            void encode_length(long length) {
                if (length < 128) {
                    data->push_back(length);
                    return;
                }

                // This doesn't deal with the zero case, but that's covered above.

                // Create byte array.
                std::vector<unsigned char> lbytes;
                while (length != 0) {
                    lbytes.push_back(length & 0xff);
                    length /= 256;
                }

                // Length of the length.  High bit is set.
                data->push_back(lbytes.size() | 0x80);

                // Put bytes in data, in reverse order.
                std::copy(lbytes.rbegin(), lbytes.rend(), back_inserter(*data));

            }

            /** Encodes a string. */
            void encode_string(tag_class cls, long tag, 
                               const std::string& s) {
                data->clear();
                encode_tag(cls, tag);
                encode_length(s.length());

                // Encode string.
                std::copy(s.begin(), s.end(), back_inserter(*data));

            }

            /** Encodes a string. */
            void encode_string(tag_class cls, long tag, 
                               const std::vector<unsigned char>& s) {
                data->clear();
                encode_tag(cls, tag);
                encode_length(s.size());

                // Encode string.
                std::copy(s.begin(), s.end(), back_inserter(*data));

            }

            /** Encodes a string. */
            void encode_string(tag_class cls, long tag, 
                               const std::vector<unsigned char>::const_iterator& s,
                               const std::vector<unsigned char>::const_iterator& e) {
                data->clear();
                encode_tag(cls, tag);
                encode_length(e - s);

                // Encode string.
                std::copy(s, e, back_inserter(*data));

            }

            /** Encodes a string. */
            void encode_oid(tag_class cls, long tag, 
                            int* oid, int len) {
                data->clear();
                encode_tag(cls, tag);
                encode_length(len);

                // Encode string.
                std::copy(oid, oid + len, back_inserter(*data));

            }

            /** Encodes an INTEGER. */
            void encode_int(tag_class cls, long tag, int64_t val) {

                std::vector<unsigned char> vbytes;

                integer<>(val).encode(vbytes);

                data->clear();
                encode_tag(cls, tag);
                encode_length(vbytes.size());

                // Encode string.
                std::copy(vbytes.rbegin(), vbytes.rend(), back_inserter(*data));

            }

            /** Encodes a string. */
            void encode_construct(tag_class cls, long tag, 
                                  const std::list<berpdu*>& pdus) {

                data->clear();
                encode_tag(cls, 0x20 | tag);

                long length = 0;
                for(std::list<berpdu*>::const_iterator it = pdus.begin();
                    it != pdus.end();
                    it++) {
                    length += (*it)->data->size();
                }
	    
                encode_length(length);

                for(std::list<berpdu*>::const_iterator it = pdus.begin();
                    it != pdus.end();
                    it++)
                    std::copy((*it)->data->begin(), (*it)->data->end(), 
                              back_inserter(*data));

            }

            /** Encodes a NULL. */
            void encode_null(tag_class cls, long tag) {

                data->clear();
                encode_tag(cls, tag);
                encode_length(0);

            }

            /** Decodes a string. */
            void decode_string(std::string& str) const {
                int start = content_start();
                int length = get_length();
	    
                str.clear();
                str.append(data->begin() + start,
                           data->begin() + start + length);

            }

            void decode_vector(std::vector<unsigned char>& vec) const {

                int start = content_start();
                int length = get_length();
	    
                vec.assign(data->begin() + start,
                           data->begin() + start + length);

            }

            /** Decodes a string. */
            void decode_construct(std::list<berpdu>& pdus) const {

                long pos = 0;
                decode_tag(pos);
                long length = decode_length(pos);

                long end = pos + length;

                pdus.clear();

                while (pos < end) {
                    long start = pos;
                    decode_tag(pos);
                    length = decode_length(pos);
                    pos += length;

                    pdus.push_back(berpdu());
                    berpdu& p = pdus.back();
                    p.data->assign(data->begin() + start, data->begin() + pos);

                }

            }

            /** Extracts an INTEGER from a PDU. */
            long decode_int() {

                integer<> i;

                int start = content_start();
                int length = get_length();

                std::vector<unsigned char> vbytes;
                std::copy(data->begin() + start, data->begin() + start + length,
                          back_inserter(vbytes));

                i.decode(vbytes);

                return i.value;

            }

            /** Waits for a complete BER PDU from a socket and returns it. */
            bool read_pdu(tcpip::stream_socket& sock);

        };

    };

};

#endif

