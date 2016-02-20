// Copyright 2015, Broala LLC. All rights reserved.

#ifndef BRO_PLUGIN_BROALA_PE_XOR
#define BRO_PLUGIN_BROALA_PE_XOR

#include <plugin/Plugin.h>

namespace plugin {
namespace Broala_PE_XOR {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
