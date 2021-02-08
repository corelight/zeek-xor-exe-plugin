// Copyright 2017, Corelight, Inc. All rights reserved.

#include "zeek/plugin/Plugin.h"
#include "zeek/file_analysis/Component.h"
#include "PE_XOR.h"

namespace zeek::plugin::detail::Corelight_PE_XOR  {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::file_analysis::Component("PE_XOR", zeek::file_analysis::detail::PE_XOR::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Corelight::PE_XOR";
		config.description = "Plugin to detect and decrypt XOR-encrypted EXEs";
		return config;
		}
} plugin;

}
