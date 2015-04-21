event bro_init()
	{
	print "Plugin initialized";
	}


event file_sniff(f: fa_file, meta: fa_metadata)
	{
	Files::add_analyzer(f, Files::ANALYZER_PE_XOR);
	}