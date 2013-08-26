
#include <socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/un.h>

tcpip::ip_address tcpip::ip_address::my_address()
{

  int ret;
  struct utsname uts;
  struct hostent *hent;

  ret = uname(&uts);
  if (ret < 0)
      return ip_address(127 << 24 | 1);

  hent = gethostbyname(uts.nodename);
  if (hent == NULL)
      return ip_address(127 << 24 | 1);

  struct in_addr addr;
  memcpy(&addr, hent->h_addr_list[0], sizeof(addr));
  return ip_address((long)(ntohl(addr.s_addr)));

}

unsigned short tcpip::tcp_socket::bound_port()
{

    struct sockaddr_in addr;

    socklen_t len = sizeof(addr);

    int ret = getsockname(sock, (struct sockaddr *) &addr, &len);
    if (ret < 0)
	throw std::runtime_error("Couldn't get socket address.");

    return ntohs(addr.sin_port);

}

void tcpip::tcp_socket::connect(const std::string& hostname, int port)
{

    create();

    struct hostent* hent = ::gethostbyname(hostname.c_str());
    if (hent == 0)
	throw std::runtime_error("Couldn't map hostname to address.");
	    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    memcpy(&addr.sin_addr.s_addr, hent->h_addr_list[0], 
	   sizeof(addr.sin_addr.s_addr));

    int ret = ::connect(sock, (sockaddr*) &addr, sizeof(addr));
    if (ret < 0)
	throw std::runtime_error("Couldn't connect to host.");

}

void tcpip::udp_socket::connect(const std::string& hostname, int port)
{

    create();

    struct hostent* hent = ::gethostbyname(hostname.c_str());
    if (hent == 0)
	throw std::runtime_error("Couldn't map hostname to address.");
	    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    memcpy(&addr.sin_addr.s_addr, hent->h_addr_list[0], 
	   sizeof(addr.sin_addr.s_addr));

    int ret = ::connect(sock, (sockaddr*) &addr, sizeof(addr));
    if (ret < 0)
	throw std::runtime_error("Couldn't connect to host.");

}

bool tcpip::tcp_socket::poll(float timeout) 
{
    struct pollfd fds;
    fds.fd = sock;
    fds.events = POLLIN|POLLPRI;
    int ret = ::poll(&fds, 1, (int) (timeout * 1000));
    if (ret < 0) {
	if (errno != EINTR)
	    throw std::runtime_error("Socket poll failed");
	else
	    return false; // Treat EINTR as timeout.
    }
    
    if (ret == 0) return false;

    if (fds.revents & POLLERR)
	throw std::runtime_error("Socket in error");

    if (fds.revents & POLLHUP)
	throw std::runtime_error("Hangup");

    if (fds.revents & POLLNVAL)
	throw std::runtime_error("Socket closed");

    if (fds.revents)
	return true;
    else
	return false;
}

bool tcpip::udp_socket::poll(float timeout) 
{
    struct pollfd fds;
    fds.fd = sock;
    fds.events = POLLIN|POLLPRI;
    int ret = ::poll(&fds, 1, (int) (timeout * 1000));
    if (ret < 0) {
	if (errno != EINTR)
	    throw std::runtime_error("Socket poll failed");
	else
	    return false; // Treat EINTR as timeout.
    }
    
    if (ret == 0) return false;

    if (fds.revents & POLLERR)
	throw std::runtime_error("Socket in error");

    if (fds.revents & POLLHUP)
	throw std::runtime_error("Hangup");

    if (fds.revents & POLLNVAL)
	throw std::runtime_error("Socket closed");

    if (fds.revents)
	return true;
    else
	return false;
}

int tcpip::tcp_socket::read(std::vector<unsigned char>& buffer, int len)
{
    int needed = len;
    int got = 0;
    
    while (needed > 0) {

	if (bufsize == 0) {
	    bufstart = 0;
	    bufsize = ::recv(sock, buf, buflen, 0);
	    if (bufsize == 0)
		return got;
	    if (bufsize < 0)
		throw std::runtime_error("Socket error");
	}

	if (bufsize > 0) {
	    if (needed >= bufsize) {
		buffer.insert(buffer.end(), buf + bufstart,
			      buf + bufstart + bufsize);
		got += bufsize;
		needed -= bufsize;
		bufsize = 0;
	    } else {
		buffer.insert(buffer.end(), buf + bufstart,
			      buf + bufstart + needed);
		bufsize -= needed;
		bufstart += needed;
		got += needed;
		needed = 0;
	    }
	}

    }
	    
    return got;
}

int tcpip::udp_socket::read(std::vector<unsigned char>& buffer, int len)
{

    char tmp[len];

    int ret = ::recv(sock, tmp, len, 0);
    if (ret < 0)
	throw std::runtime_error("Socket error");

    buffer.resize(ret);
    copy(tmp, tmp + ret, buffer.begin());

    return ret;

}

int tcpip::udp_socket::read(char* buffer, int len)
{

    int ret = ::recv(sock, buffer, len, 0);
    if (ret < 0)
	throw std::runtime_error("Socket error");

    return ret;

}

int tcpip::tcp_socket::read(char* buffer, int len)
{
    int needed = len;
    int got = 0;
	    
    while (needed > 0) {

	if (bufsize == 0) {
	    bufstart = 0;
	    bufsize = ::recv(sock, buf, buflen, 0);
	    if (bufsize == 0)
		return got;
	    if (bufsize < 0)
		throw std::runtime_error("Socket error");
	}

	if (bufsize > 0) {
	    if (needed >= bufsize) {
		memcpy(buffer + got, buf + bufstart, bufsize);
		got += bufsize;
		needed -= bufsize;
		bufsize = 0;
	    } else {
		memcpy(buffer + got, buf + bufstart, needed);
		bufsize -= needed;
		bufstart += needed;
		got += needed;
		needed = 0;
	    }
	}

    }
	    
    return got;
}

void tcpip::tcp_socket::readline(std::string& line)
{
    unsigned char c;
    line = "";
    while(1) {
	if (bufsize > 0) {
	    c = buf[bufstart];
	    bufstart++;
	    bufsize--;
	} else {
	    int ret = ::recv(sock, buf, buflen, 0);
	    bufsize = ret;
	    bufstart = 0;
	    if (ret <= 0 && line.size() > 1)
		return;
	    if (ret <= 0)
		throw std::runtime_error("EOF on socket.");
	    continue;
	}
	if (c == '\r') continue;
	if (c == '\n') return;
	line += c;
    }
}

void tcpip::tcp_socket::bind(int port)
{

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    create();
	    
    /* Re-use the socket address in case it's in TIME_WAIT state. */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &opt,
	       sizeof(opt));
	    
    int ret = ::bind(sock, (struct sockaddr*) &addr, sizeof(addr));
    if (ret < 0) {
	::close(sock);
	throw std::runtime_error("Socket bind failed.");
    }
    socklen_t slen = sizeof(addr);
    ret = ::getsockname(sock, (struct sockaddr*) &addr, &slen);
    if (ret < 0) {
	::close(sock);
	throw std::runtime_error("Socket address failed.");
    }
    port = ntohs(addr.sin_port);

}

void tcpip::udp_socket::bind(int port)
{

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    create();

    int ret = ::bind(sock, (struct sockaddr*) &addr, sizeof(addr));
    if (ret < 0) {
	::close(sock);
	throw std::runtime_error("Socket bind failed.");
    }
    socklen_t slen = sizeof(addr);
    ret = ::getsockname(sock, (struct sockaddr*) &addr, &slen);
    if (ret < 0) {
	::close(sock);
	throw std::runtime_error("Socket address failed.");
    }
    port = ntohs(addr.sin_port);

}

void tcpip::socket::readline(std::string& line)
{
    unsigned char c;
    line = "";
    while(1) {
	int ret = read((char*) &c, 1);
	if (ret <= 0 && line.size() > 1)
	    return;
	if (ret <= 0)
	    throw std::runtime_error("EOF on socket.");
	if (c == '\r') continue;
	if (c == '\n') return;
	line += c;
    }
}

std::ostream& operator<<(std::ostream& o, const tcpip::address& addr) {
    std::string s;
    addr.to_string(s);
    o << s;
    return o;
}

void tcpip::unix_socket::connect(const std::string& path)
{

    create();

    struct sockaddr_un address;

    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, path.c_str());

    int ret = ::bind(sock, reinterpret_cast<struct sockaddr *>(&address),
		   sizeof(address));
    if (ret < 0)
	throw std::runtime_error("Socket bind failed");

}

bool tcpip::unix_socket::poll(float timeout) 
{
    struct pollfd fds;
    fds.fd = sock;
    fds.events = POLLIN|POLLPRI;
    int ret = ::poll(&fds, 1, (int) (timeout * 1000));
    if (ret < 0) {
	if (errno != EINTR)
	    throw std::runtime_error("Socket poll failed");
	else
	    return false; // Treat EINTR as timeout.
    }
    
    if (ret == 0) return false;

    if (fds.revents & POLLERR)
	throw std::runtime_error("Socket in error");

    if (fds.revents & POLLHUP)
	throw std::runtime_error("Hangup");

    if (fds.revents & POLLNVAL)
	throw std::runtime_error("Socket closed");

    if (fds.revents)
	return true;
    else
	return false;
}

int tcpip::unix_socket::read(std::vector<unsigned char>& buffer, int len)
{

    char tmp[len];

    int ret = ::recv(sock, tmp, len, 0);
    if (ret < 0)
	throw std::runtime_error("Socket error");

    buffer.resize(ret);
    copy(tmp, tmp + ret, buffer.begin());

    return ret;

}

int tcpip::unix_socket::read(char* buffer, int len)
{

    int ret = ::recv(sock, buffer, len, 0);
    if (ret < 0)
	throw std::runtime_error("Socket error");

    return ret;

}

void tcpip::unix_socket::bind(const std::string& path)
{

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path.c_str());

    create();

    unlink(path.c_str());

    int ret = ::bind(sock, (struct sockaddr*) &addr, sizeof(addr));
    if (ret < 0) {
	::close(sock);
	throw std::runtime_error("Socket bind failed.");
    }

}

