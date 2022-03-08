# This tests a XOR-encoded EXE downloaded from the Nuclear Exploit Kit.
# See: http://malware-traffic-analysis.net/2015/04/09/index.html

# @TEST-EXEC: zeek -r $TRACES/2015-04-09-Nuclear-EK-traffic.pcap %INPUT > output
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto note msg sub src dst p < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log

@load Corelight/PE_XOR
