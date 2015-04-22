##! Detect Windows executable (PE) files that are XOR-encrypted.
##! The XOR key can be up to 30 characters long.

@load base/frameworks/files
@load base/frameworks/notice


module Broala;

export {
	redef enum Notice::Type += {
		## An XOR-encrypted PE file was seen
		XOR_Encrypted_PE_File_Seen
	};
}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	Files::add_analyzer(f, Files::ANALYZER_PE_XOR);
	}

event pe_xor_found(f: fa_file, key: string, decrypted_fuid: string)
	{
	local message = fmt("Executable file XOR encrypted with key '%s'", key);
	local n: Notice::Info = Notice::Info($ts=network_time(), $note=XOR_Encrypted_PE_File_Seen, $msg=message, $sub=fmt("Decrypted PE fuid is %s", decrypted_fuid), $f=f);
	NOTICE(n);
	}

event pe_xor_not_found(f: fa_file)
	{
	Files::remove_analyzer(f, Files::ANALYZER_PE_XOR);
	}
