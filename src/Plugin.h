// Copyright 2017, Corelight, Inc. All rights reserved.

#pragma once

#include <plugin/Plugin.h>
#include "analyzer/Component.h"

namespace plugin {
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

