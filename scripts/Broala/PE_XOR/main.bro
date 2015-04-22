event file_sniff(f: fa_file, meta: fa_metadata)
	{
	Files::add_analyzer(f, Files::ANALYZER_PE_XOR);
	}

event pe_xor_found(f: fa_file, key: string)
	{
	print fmt("%s is XOR-encrypted with key '%s'", f$id, key);
	}

event pe_xor_not_found(f: fa_file)
	{
	print "Key not found";
	Files::remove_analyzer(f, Files::ANALYZER_PE_XOR);
	}
