
#ifndef CYBERMON_SOCKET_H
#define CYBERMON_SOCKET_H

#include <openssl/ssl.h>

#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace tcpip {

    // Legacy?
    class ip_address {
      private:
	uint32_t a;
      public:
	void get(uint32_t& addr) { addr = a; }
	void get(std::string& addr) {
	    std::ostringstream buf;
	    buf << ((a >> 24) & 0xff) << "."
		<< ((a >> 16) & 0xff) << "."
		<< ((a >> 8) & 0xff) << "."
		<< (a & 0xff);
	    addr = buf.str();
	}
	ip_address(uint32_t addr) {
	    a = addr;
	}
	static ip_address my_address();
    };

    // IP address base class.
    class address {
      public:
        virtual ~address() {}

	enum {ipv4, ipv6 } universe;
	std::vector<unsigned char> addr;
	virtual void to_string(std::string&) const = 0;
	virtual bool operator<(const address& a) const {
	    return addr < a.addr;
	}
	virtual bool operator==(const address& a) const {
	    return addr == a.addr;
	}
    };

    /** IPv4 address */
    class ip4_address : public address {
      public:
	ip4_address() {
	    addr.resize(4);
	    universe = ipv4;
	}
	ip4_address(const std::string& a) {
	    addr.resize(4);
	    universe = ipv4;
	    from_string(a);
	}
	void from_string(const std::string& str) {
	    struct in_addr a;
	    addr.resize(4);
	    int ret = ::inet_pton(AF_INET, str.c_str(), &a);
	    if (ret <= 0) {
		throw std::runtime_error("IPv4 parse failed");
	    }
	    unsigned char* ptr = reinterpret_cast<unsigned char*>(&(a.s_addr));
	    addr.assign(ptr, ptr + 4);
	}
	void to_string(std::string& str) const {

	    struct in_addr a;

	    std::copy(addr.begin(), addr.begin() + 4, 
		      reinterpret_cast<unsigned char*>(&(a.s_addr)));

	    char dest[128];
	    ::inet_ntop(AF_INET, &a, dest, 128);
	    str = dest;
	}
        static void parse(const std::string& str, ip4_address& addr, 
                          unsigned int& mask) {

            std::string rem;

	    int pos = str.find("/");
            if (pos != -1) {
                std::string m = str.substr(pos + 1);
                std::istringstream buf(m);
                buf >> mask;
                rem = str.substr(0, pos);
                if (mask > 32) mask = 32;
            } else {
                mask = 32;
                rem = str;
            }

            addr.from_string(rem);

        }
	virtual ip4_address operator&(unsigned int mask) const {
	    ip4_address a = *this;
	    for(unsigned int i = 0; i < a.addr.size(); i++) {
		if (mask > 8) { mask -=8; continue; }
		if (mask == 0) { a.addr[i] = 0; continue; }
		
		unsigned int tmask = 255 - ((1 << (8 - mask)) - 1);
		a.addr[i] &= tmask;

		mask = 0;

	    }
	    return a;
	}
    };

    /** IPv6 address */
    class ip6_address : public address {
      public:
	ip6_address() {
	    addr.resize(16);
	    universe = ipv6;
	}
	ip6_address(const std::string& a) {
	    addr.resize(16);
	    universe = ipv6;
	    from_string(a);
	}
	void from_string(const std::string& str) {
	    struct in6_addr a;
	    int ret = ::inet_pton(AF_INET6, str.c_str(), &a);
	    if (ret <= 0) {
		throw std::runtime_error("IPv4 parse failed");
	    }
	    addr.assign(a.s6_addr, a.s6_addr + 16);
	}
	void to_string(std::string& str) const {
	    struct in6_addr a;
	    std::copy(addr.begin(), addr.begin() + 16, a.s6_addr);
	    char dest[128];
	    ::inet_ntop(AF_INET6, &a, dest, 128);
	    str = dest;
	}
        static void parse(const std::string& str, ip6_address& addr, 
                          unsigned int& mask) {
            
            std::string rem;

	    int pos = str.find("/");
            if (pos != -1) {
                std::string m = str.substr(pos + 1);
                std::istringstream buf(m);
                buf >> mask;
                rem = str.substr(0, pos);
                if (mask > 128) mask = 128;
            } else {
                mask = 128;
                rem = str;
            }

            addr.from_string(rem);

        }
	virtual ip6_address operator&(unsigned int mask) const {
	    ip6_address a = *this;
	    for(unsigned int i = 0; i < a.addr.size(); i++) {
		if (mask > 8) { mask -=8; continue; }
		if (mask == 0) { a.addr[i] = 0; continue; }
		
		unsigned int tmask = 255 - ((1 << (8 - mask)) - 1);
		a.addr[i] &= tmask;

		mask = 0;

	    }
	    return a;
	}
    };

    /** A socket. Abstract class for all socketry. */
    class socket {
      public:
      
	/** Destructor */
	virtual ~socket() {}

	/** Read some data from a socket. */
	virtual int read(char* buffer, int len) = 0;
	
	/** Write some data from a socket */
	virtual int write(const char* buffer, int len) = 0;

	// Short-hand
	typedef std::vector<unsigned char>::const_iterator const_iterator;

	/** Write to the socket. */
	virtual int write(const_iterator& start,
			  const_iterator& end) {
	    unsigned char tmp[end - start];
	    copy(start, end, tmp);
	    return write((char*) tmp, end - start);
	}

	/** Write to the socket. */
	virtual int write(const std::vector<unsigned char>& buffer) {
	    unsigned char tmp[buffer.size()];
	    copy(buffer.begin(), buffer.end(), tmp);
	    return write((char*) tmp, buffer.size());
	}
	
	/** Write to the socket. */
	virtual int write(const std::string& str) {
	    return write(str.c_str(), str.length());
	}

    };

    class stream_socket : public socket {
      public:
	virtual ~stream_socket() {}

	/** Read a line of text, LF. CR is discarded. */
	virtual void readline(std::string& line);

	virtual void close() = 0;

    };

    /** A TCP socket. */
    class tcp_socket : public stream_socket {
      private:
	static const int buflen = 8192;
	int bufstart;
	int bufsize;
	char buf[buflen];
      public:
	int sock;
      private:

	/** Socket port number. */
	int port;

      public:

	/** Bind to port */
	void bind(int port = 0);

	/** Create a TCP socket. */
	tcp_socket() { 
	    sock = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	    if (sock < 0)
		throw std::runtime_error("Socket creation failed.");
	    bufstart = bufsize = 0;
	};

	bool is_open() {
	    return sock != -1;
	}

	/** Read from the socket. With buffering. */
	virtual int read(char* buffer, int len);

	/** Read from the socket. With buffering. */
	virtual int read(std::string& buf, int len) {
	    char tmp[len];
	    int ret = read(tmp, len);
	    buf.assign(tmp, len);
	    return ret;
	}

	/** Read from the socket. With buffering. */
	virtual int read(std::vector<unsigned char>& buffer, int len);

	/** Write to the socket. */
	virtual int write(const char* buffer, int len) {
	    return ::write(sock, buffer, len);
	}

	using socket::write;

	unsigned short bound_port();

	/** Put socket in listen mode. */
	virtual void listen(int backlog=10) {
	    ::listen(sock, backlog);
	}

	/** Accept a connection. */
	virtual void accept(tcp_socket& conn) {
	    int ns = ::accept(sock, 0, 0);
	    if (-1 == ns) {
		throw std::runtime_error("Socket accept failed");
	    }
	    conn.sock = ns;
	    conn.port = port;
	}

	/** Connection to a remote service */
	virtual void connect(const std::string& hostname, int port);

	/** Close the connection. */
	virtual void close() {
            if (sock >= 0) {
		::shutdown(sock, SHUT_RDWR);
                ::close(sock);
		sock = -1;
            }
	}

	/** Destructor. */
	virtual ~tcp_socket() {
	    close();
	}
	
	/** Poll, waits for timeout (in seconds) and returns true if there's
	    activity on the socket. */
	virtual bool poll(float timeout);

    };

    /** A UDP socket. */
    class udp_socket : public socket {
      public:
	int sock;
      private:

	/** Socket port number. */
	int port;

      public:

	/** Bind to port */
	void bind(int port = 0);

	/** Create a UDP socket. */
	udp_socket() { 
	    sock = ::socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	    if (sock < 0)
		throw std::runtime_error("Socket creation failed.");
	};

	/** Read a datagram from the socket. With buffering. */
	virtual int read(char* buffer, int len);

	/** Read from the socket. With buffering. */
	virtual int read(std::vector<unsigned char>& buffer, int len);

	/** Write to the socket. */
	virtual int write(const char* buffer, int len) {
	    return ::write(sock, buffer, len);
	}

	using socket::write;

	/** Connection to a remote service */
	virtual void connect(const std::string& hostname, int port);

	/** Close the connection. */
	virtual void close() {
            if (sock >= 0) {
		::shutdown(sock, SHUT_RDWR);
                ::close(sock);
		sock = -1;
            }
	}

	/** Destructor. */
	virtual ~udp_socket() {
	    close();
	}
	
	/** Poll, waits for timeout (in seconds) and returns true if there's
	    activity on the socket. */
	virtual bool poll(float timeout);

    };

    /** A UNIX socket (datagram mode). */
    class unix_socket : public socket {
      public:
	int sock;
      private:

	/** Socket port number. */
	int port;

      public:

	/** Bind to port */
	void bind(const std::string& name);

	/** Create a UNIX socket. */
	unix_socket() { 
	    sock = ::socket(PF_UNIX, SOCK_DGRAM, 0);
	    if (sock < 0)
		throw std::runtime_error("Socket creation failed.");
	};

	/** Read a datagram from the socket. With buffering. */
	virtual int read(char* buffer, int len);

	/** Read from the socket. With buffering. */
	virtual int read(std::vector<unsigned char>& buffer, int len);

	/** Write to the socket. */
	virtual int write(const char* buffer, int len) {
	    return ::write(sock, buffer, len);
	}

	using socket::write;

	/** Connection to a remote service */
	virtual void connect(const std::string& path);

	/** Close the connection. */
	virtual void close() {
            if (sock >= 0) {
		::shutdown(sock, SHUT_RDWR);
                ::close(sock);
		sock = -1;
            }
	}

	/** Destructor.  You must call close() before destroying socket,
	    otherwise a file descriptor gets leaked. */
	virtual ~unix_socket() {
	    close();
	}
	
	/** Poll, waits for timeout (in seconds) and returns true if there's
	    activity on the socket. */
	virtual bool poll(float timeout);

    };

    /** A raw IP socket (HDRINCL mode). */
    class raw_socket : public socket {
      public:
	int sock;
      private:

	/** Socket port number. */
	int port;

      public:

	/** Create a UNIX socket. */
	raw_socket() { 
	    sock = ::socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	    if (sock < 0)
		throw std::runtime_error("Socket creation failed.");
	    int y = 1;
	    int ret = setsockopt(sock, 0, IP_HDRINCL, (char *) &y, sizeof(y));
	    if (ret < 0)
		throw std::runtime_error("Couldn't set IP_HDRINCL sock opt");

	};

	/** Write to the socket. */
	virtual int write(const char* buffer, int len) {
	    return ::write(sock, buffer, len);
	}

	using socket::write;

	virtual int read(char* buffer, int len) {
	    return ::read(sock, buffer, len);
	}

	/** Connection to a remote service */
	virtual void connect(const std::string& addr);

	/** Close the connection. */
	virtual void close() {
            if (sock >= 0) {
		::shutdown(sock, SHUT_RDWR);
                ::close(sock);
		sock = -1;
            }
	}

	/** Destructor. */
	virtual ~raw_socket() {
	    close();
	}

    };

    /** An SSL/TLS socket. */
    class ssl_socket : public stream_socket {
      private:
	static const int buflen = 8192;
	int bufstart;
	int bufsize;
	char buf[buflen];
      public:
	int sock;
      private:

	/** Socket port number. */
	int port;

	SSL* ssl;
	SSL_CTX* context;

	static bool ssl_init;

      public:

	/** Provide certificate. */
	void use_certificate_file(const std::string& f) {
	    if (context == 0)
		throw std::runtime_error("No SSL context.");
	    int ret = SSL_CTX_use_certificate_file(context, f.c_str(),
						   SSL_FILETYPE_PEM);
	    if (ret < 0)
		throw std::runtime_error("Couldn't load certificate file.");
	}

	/** Provide private key. */
	void use_key_file(const std::string& f) {
	    if (context == 0)
		throw std::runtime_error("No SSL context.");
	    int ret = SSL_CTX_use_PrivateKey_file(context, f.c_str(),
						  SSL_FILETYPE_PEM);
	    if (ret < 0)
		throw std::runtime_error("Couldn't load private key file.");
	}

	/** Provide CA chain. */
	void use_certificate_chain_file(const std::string& f) {
	    if (context == 0)
		throw std::runtime_error("No SSL context.");
	    int ret = SSL_CTX_load_verify_locations(context, f.c_str(), 0);
	    if (ret < 0)
		throw std::runtime_error("Couldn't load certificate file.");
	}

	/** Bind to port */
	void bind(int port = 0);

	/** Constructor. */
	ssl_socket() { 
	    bufstart = bufsize = 0;

	    if (!ssl_init) {
		SSL_library_init();
		ssl_init = true;
	    }

	    // FIXME: Should probably use TLS_method
	    // context = SSL_CTX_new(TLSv1_2_method());
	    context = SSL_CTX_new(SSLv23_method());
	    if (context == 0)
		throw std::runtime_error("Couldn't initialise SSL context.");

	    ssl = SSL_new(context);
	    if (ssl == 0)
		throw std::runtime_error("Couldn't initialise SSL.");

	    sock = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	    if (sock < 0)
		throw std::runtime_error("Socket creation failed.");

	    SSL_set_fd(ssl, sock);
	    
	};

	bool is_open() {
	    return sock != -1;
	}

	/** Read from the socket. With buffering. */
	virtual int read(char* buffer, int len);

	/** Read from the socket. With buffering. */
	virtual int read(std::string& buf, int len) {
	    char tmp[len];
	    int ret = read(tmp, len);
	    buf.assign(tmp, len);
	    return ret;
	}

	/** Read from the socket. With buffering. */
	virtual int read(std::vector<unsigned char>& buffer, int len);

	/** Write to the socket. */
	virtual int write(const char* buffer, int len) {
	    return SSL_write(ssl, buffer, len);
	}

	using socket::write;
	
	// Short-hand
	typedef std::vector<unsigned char>::const_iterator const_iterator;

	unsigned short bound_port();

	/** Put socket in listen mode. */
	virtual void listen(int backlog=10) {
	    ::listen(sock, backlog);
	}

	/** Accept a connection. */
	virtual void accept(ssl_socket& conn) {
	    int ns = ::accept(sock, 0, 0);
	    if (-1 == ns) {
		throw std::runtime_error("Socket accept failed");
	    }
	    conn.sock = ns;
	    conn.port = port;
	    int ret = SSL_accept(ssl);
	    if (ret < 0)
		throw std::runtime_error("SSL accept failed");
	}

	/** Connection to a remote service */
	virtual void connect(const std::string& hostname, int port);

	/** Close the connection. */
	virtual void close() {
	    if (ssl)
		SSL_shutdown(ssl);
            if (sock >= 0) {
		::shutdown(sock, SHUT_RDWR);
                ::close(sock);
		sock = -1;
            }
	}

	/** Destructor.  You must call close() before destroying socket,
	    otherwise a file descriptor gets leaked. */
	virtual ~ssl_socket() {
	    if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = 0;
	    }
	    if (context) {
		SSL_CTX_free(context);
		context = 0;
	    }
	}
	
	/** Poll, waits for timeout (in seconds) and returns true if there's
	    activity on the socket. */
	virtual bool poll(float timeout);

    };

};

std::ostream& operator<<(std::ostream& o, const tcpip::address& addr);

#endif

