// Copyright 2015, Broala LLC. All rights reserved.

#include "Plugin.h"

#include "PE_XOR.h"

namespace plugin { namespace Broala_PE_XOR { Plugin plugin; } }

using namespace plugin::Broala_PE_XOR;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::file_analysis::Component("PE_XOR", ::file_analysis::PE_XOR::Instantiate));

	plugin::Configuration config;
	config.name = "Broala::PE_XOR";
	config.description = "Plugin to detect and decrypt XOR-encrypted EXEs";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
