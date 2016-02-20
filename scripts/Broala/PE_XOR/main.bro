##! Detect Windows executable (PE) files that are XOR-encrypted.
##! The XOR key can be up to 30 characters long.
##!
##! Copyright 2015, Broala LLC. All rights reserved.

@load base/frameworks/files
@load base/frameworks/notice
@load base/files/pe

module Broala;

export {
	redef enum Notice::Type += {
		## An XOR-encrypted PE file was seen
		XOR_Encrypted_PE_File_Seen
	};

	type XORbinary: record {
		## The key used to decrypt the file.
		key:  string &optional;
		## The original file.
		f:    fa_file &optional;
	};
}

global possible_xor_bins: table[string] of XORbinary &write_expire=1hr;

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	Files::add_analyzer(f, Files::ANALYZER_PE_XOR);
	}

event pe_file_header(f: fa_file, h: PE::FileHeader)
	{
	if ( f?$source && "XOR" in f$source )
		{
		local key = to_upper(string_to_ascii_hex(possible_xor_bins[f$id]$key));
		local message = fmt("Executable file XOR encrypted with hex key 0x%s", key);
		local submessage = fmt("Decrypted File ID: %s", f$id);
		local n: Notice::Info = Notice::Info($ts=network_time(),
		                                     $note=XOR_Encrypted_PE_File_Seen,
		                                     $msg=message,
		                                     $sub=submessage,
		                                     $f=possible_xor_bins[f$id]$f);
		NOTICE(n);
		}
	}

event pe_xor_found(f: fa_file, key: string, decrypted_fuid: string)
	{
	possible_xor_bins[decrypted_fuid] = XORbinary($key=key, $f=f);
	}

event pe_xor_not_found(f: fa_file)
	{
	Files::remove_analyzer(f, Files::ANALYZER_PE_XOR);
	}
