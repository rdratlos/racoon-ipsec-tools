DESC="resolved's own stub AND a second, independent forwarder (unbound) both bound to port 53 at once -- §C conflict reporting: every listener must be reported, none silently picked."
EXPECT_GLIBC_READER_SUFFIX="/run/systemd/resolve/stub-resolv.conf"
EXPECT_NSS_RESOLVE="yes"
EXPECT_DIVERGENT="no"
EXPECT_PARALLEL_UNLINKED="no"
EXPECT_PORT53_COUNT="2"
EXPECT_PORT53_CONTAINS="LISTENER	udp	127.0.0.53	53	100	/usr/lib/systemd/systemd-resolved	stub	ss
LISTENER	udp	127.0.0.1	53	300	/usr/sbin/unbound	forwarder	ss"
EXPECT_PORT53_BROKEN="no"
