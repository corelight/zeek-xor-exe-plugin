// Copyright 2017-2021, Corelight, Inc. All rights reserved.

#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin {
namespace Corelight_PE_XOR {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

