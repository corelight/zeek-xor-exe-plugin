// Copyright 2017-2021, Corelight, Inc. All rights reserved.

#pragma once

#include <string>

#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Analyzer.h"

#include "pe_xor.bif.h"

namespace zeek::file_analysis::detail {

/**
 * Analyze XOR-encrypted Portable Executable files
 */
class PE_XOR : public file_analysis::Analyzer {
public:
	~PE_XOR() override;

	static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file)
		{ return new PE_XOR(args, file); }

	bool DeliverStream(const u_char* data, uint64_t len) override;
	bool EndOfFile() override;

protected:
	PE_XOR(RecordValPtr args, file_analysis::File* file);

	bool FindKey(const u_char* data);

private:
	uint8_t key_0;
	uint8_t key_1;

	uint64_t offset;

	char* key;
	uint8_t key_len;

	bool key_found;
	bool skip;

	std::string file_id;
};

} // namespace zeek::file_analysis::detail


