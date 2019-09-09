
/****************************************************************************

 ****************************************************************************
 *** OVERVIEW
 ****************************************************************************

Simple software-based probe.

Usage:

    cyberprobe <config-file>

****************************************************************************/

#include <sstream>
#include <fstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <cyberprobe/probe/configuration.h>
#include <cyberprobe/probe/delivery.h>

using namespace cyberprobe::probe;

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

