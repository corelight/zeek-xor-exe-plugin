
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginXorExe)

include(ZeekPlugin)

zeek_plugin_begin(Corelight PE_XOR)
zeek_plugin_cc(src/PE_XOR.cc src/Plugin.cc)
zeek_plugin_bif(src/pe_xor.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()

