
#include "Plugin.h"

namespace plugin { namespace Broala_PE_XOR { Plugin plugin; } }

using namespace plugin::Broala_PE_XOR;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Broala::PE_XOR";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
