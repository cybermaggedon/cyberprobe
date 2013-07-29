
/****************************************************************************

****************************************************************************
*** OVERVIEW
****************************************************************************

Simple software-based probe.

Usage:

    cyberprobe <config-file>

****************************************************************************/

#include <nhis11.h>
#include <sstream>
#include <fstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "socket.h"

#include "thread.h"
#include "packet_capture.h"
#include "resource.h"
#include "specification.h"
#include "delivery.h"
#include "sender.h"
#include "xml.h"
#include "target.h"
#include "capture.h"
#include "interface.h"
#include "endpoint.h"
#include "config.h"
#include "parameter.h"


////////////////////////////////////////////////////////////////////////////
//
// MAIN
//
////////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv)
{

    // Usage if arguments aren't right.
    if (argc != 2) {
	std::cerr << "Usage:" << std::endl
		  << "  cyberprobe <config>" 
		  << std::endl;
	exit(1);
    }

    // Only one argument, a configuration file.
    std::string config = argv[1];
    
    // Block SIGPIPE.
    signal(SIGPIPE, SIG_IGN);

    // Create the delivery engine.
    delivery deliv;

    // Create the configuration manager.
    config_manager cm(deliv);

    // Loop forever, checking the configuration file for a change.
    while (1) {
	cm.check(config);
	::sleep(1);
    }

}

