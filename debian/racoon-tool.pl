#!/usr/bin/perl -w
#
# Script for configuring linux 2.6.x IPSEC 
#
# Copyright 2004 Matthew Grant, Catalyst IT Ltd, GPL2
#

# Loads and unloads all modules needed for IPSEC

# Writes configuration files for racoon

# Administers SPD in kernel using setkey program

# Basically imitates Free S/WAN without all the kludgy garbage...

# We are only dealing with IP addresses
use integer;

sub mod_ls ();
sub mod_load ($);
sub mod_unload ($);
sub usage ();
sub mod_start();
sub mod_stop();
sub sad_flush();
sub spd_flush();
sub parse_config();
sub ipsec_start();
sub ipsec_stop();
sub ipsec_load();
sub spd_show();
sub sad_show();
sub parse_spd(\@\%);
sub conn_dump_list();
sub peer_dump_list();
sub global_dump_list();
sub spd_dump_list(\@\%);
sub prog_warn($$;$);
sub prog_die($;$);
sub match_spd_connection(\@\%);
sub conn_down_handle($);
sub conn_down (\@\%$;$$);
sub conn_list($);
sub log_backend();
sub conn_up_handle($);
sub conn_menu($);
sub racoon_write_config($$);
sub racoon_configure(;$);
sub prop_get_indexes (\%);
sub prop_store_index (\%$);
sub conn_reload_handle($);
sub check_if_running ();
sub racoon_start();
sub racoon_stop();
sub basename($$);
sub dirname($);
sub openlog($$$);
sub syslog($$);

if ($^O =~ /linux/i ) {
	$proc_modules = "/proc/modules";
	$kver = `uname -r`; chomp $kver;
	$modpath = "/lib/modules/" . $kver;
	$modpath_ipsec = "$modpath/kernel/net/ipv4";
	$modpath_ipsec6 = "$modpath/kernel/net/ipv6";
	$modpath_xfrm = "$modpath/kernel/net/xfrm";
	$modpath_key = "$modpath/kernel/net/key";
	$modpath_crypto = "$modpath/kernel/crypto";
	$modpath_zlib = "$modpath/kernel/lib/zlib_deflate";
	$modext = ( $kver =~ /^2\.6\.|^3\./ ? ".ko" : ".o" );
	$proc_ipv4 = "/proc/sys/net/ipv4";
	$proc_ipv6 = "/proc/sys/net/ipv6";
} # endif linux


if ($^O =~ /linux|gnukfreebsd/i) {
	$setkey_cmd = "/usr/sbin/setkey";
	$confdir = "/etc/racoon";
	$vardir = "/var/lib/racoon";
	$conffile = "${confdir}/racoon-tool.conf";
	$conffiledir = "${confdir}/racoon-tool.conf.d";
	$racoon_cmd = "/usr/sbin/racoon";
	$less_cmd = "/usr/bin/less";
	$more_cmd = "/bin/more";
} elsif ($^O =~ /freebsd/i) {
	$setkey_cmd = "/usr/local/sbin/setkey";
	$confdir = "/usr/local/etc/racoon";
	$vardir = "/var/db/racoon";
	$conffile = "${confdir}/racoon-tool.conf";
	$conffiledir = "${confdir}/racoon-tool.conf.d";
	$racoon_cmd = "/usr/local/sbin/racoon";
	$less_cmd = "/usr/bin/less";
	$more_cmd = "/usr/bin/more";
} elsif ($^O =~ /netbsd/i) {
	# This set of paths is a guess, and needs confirmation
	$setkey_cmd = "/usr/sbin/setkey";
	$confdir = "/etc/racoon";
	$vardir = "/var/db/racoon";
	$conffile = "${confdir}/racoon-tool.conf";
	$conffiledir = "${confdir}/racoon-tool.conf.d";
	$racoon_cmd = "/usr/sbin/racoon";
	$less_cmd = "/usr/bin/less";
	$more_cmd = "/usr/bin/more";
} else {
	prog_die("unsupported platform - '$^O'.");
}

# Some OS kernels need time for their SAD and SPD to settle.
$quiesce = 0;
if ($^O =~ /freebsd/i) {
	$quiesce = 1; # seconds
}

$pager_cmd =  ( -x $less_cmd ? $less_cmd : $more_cmd );
@pager_flags = ( -x $less_cmd ? ( '-MMXEi' ): ());
# Handle BSD and SYSV ps...
$ps_cmd = ($^O =~ /bsd/i ? "ps axc" : "ps -e");
$psf_cmd = ($^O =~ /bsd/i ? "ps axw" : "ps -eo pid,cmd");

%fmt = ( 'normal' => 1, 'brief' => 2, 'comma' => 3 );
$global_format = $fmt{'normal'};
local $proc_id = $$;
$progname = basename($0, "");
$racoon_kill_delay = 25; # seconds

# global settings hash
my $global_proplist = 'path_pre_shared_key|path_certificate|path_script|path_racoon_conf|privsep|privsep_chroot|privsep_user|privsep_group|racoon_command|racoon_pid_file|log|listen\[[-_0-9a-z]+\]|complex_bundle';
my %global = (
		'path_pre_shared_key'	=> "$confdir/psk.txt",
		'path_certificate'	=> "$confdir/certs",
		'path_script'		=> "$confdir/scripts",
		'path_racoon_conf'	=> "${vardir}/racoon.conf",
		'privsep'		=> "off",
		'privsep_chroot'	=> "/",
		'privsep_user'		=> "racoon",
		'privsep_group'		=> "racoon",
		'racoon_command'	=> "${racoon_cmd} -f ___path_racoon_conf___",
		'racoon_pid_file'	=> "/var/run/racoon.pid",
	);

# Peer related stuff
my $peer_proplist = 'exchange_mode|encryption_algorithm\[[-_0-9a-z]+\]|hash_algorithm\[[-_0-9a-z]+\]|dh_group\[[-_0-9a-z]+\]|authentication_method\[[-_0-9a-z]+\]|remote_template|lifetime|verify_identifier|verify_cert|passive|generate_policy|my_identifier|peers_identifier|certificate_type|peers_certfile|support_mip6|send_cr|send_cert|initial_contact|proposal_check|nat_traversal|nonce_size';
my %peer_list = (	'%default' => {
			'exchange_mode'			=> 'main',
			'encryption_algorithm[0]'	=> '3des',
			'hash_algorithm[0]'		=> 'sha1',
			'dh_group[0]'			=> 'modp1024',
			'authentication_method[0]'	=> 'pre_shared_key',
			'remote_template'		=> '%default',
			# Initialised because proposal 0 is present
			'pindexes'			=> [0]
			},
			'%anonymous' 		=> {
			'passive'		=> 'on',
			'generate_policy'	=> 'on'
			} );

# Connection related stuff
my $conn_proplist = 'src_range|dst_range|src_ip|dst_ip|src_port\[[-_0-9a-z]+\]|dst_port\[[-_0-9a-z]+\]|upperspec|encap|encap\[[-_0-9a-z]+\]|mode|level|level\[[-_0-9a-z]+\]|admin_status|spdadd_template|sadadd_template|sainfo_template|pfs_group|lifetime|encryption_algorithm|authentication_algorithm|compression|id_type|auto_ah_on_esp|always_ah_on_esp|policy|policy\[[-_0-9a-z]+\]';
my @conn_required_props = ( 'src_ip', 'dst_ip');
my %connection_list = ( '%default' => {
			'admin_status' 		=> 'disabled',
			'upperspec' 		=> 'any',
			'encap' 		=> 'esp',
			'level' 		=> 'unique',
			'policy'		=> 'ipsec',
			'spdadd_template' 	=> '%default',
			'sadadd_template' 	=> '%default',
			'sainfo_template' 	=> '%default',
			'pfs_group'		=> 'modp1024',
			'encryption_algorithm'	=> 'aes,3des',
			'authentication_algorithm'	=> 'hmac_sha1,hmac_md5',
			'id_type'		=> 'address',
			'auto_ah_on_esp'	=> 'off',
			'always_ah_on_esp'	=> 'off',
			'policy'		=> 'ipsec'
			},
			'%anonymous'		=> {
			'admin_status'		=> 'disabled'
			} );

my %prop_typehash = ( 	'connection'	=> {
			'src_range' 	=> 'range',
		 	'dst_range' 	=> 'range',
			'src_ip' 	=> 'ip',
			'dst_ip'	=> 'ip',
			'src_port'	=> 'port',
			'dst_port'	=> 'port',
			'upperspec'	=> 'upperspec',
			'encap'		=> 'encap',
			'level'		=> 'level',
			'mode'		=> 'mode',
			'admin_status'	=> 'boolean',
			'spdadd_template'	=> 'template_name',
			'sadadd_template'	=> 'template_name',
			'sainfo_template'	=> 'template_name',
			'pfs_group'		=> 'pfs_group',
			'lifetime'		=> 'lifetime',
			'encryption_algorithm'	=> 'phase2_encryption',
			'authentication_algorithm' => 'phase2_auth_algorithm',
			'compression'		=> 'boolean',
			'id_type'		=> 'id_type',
			'auto_ah_on_esp'	=> 'boolean',
			'always_ah_on_esp'	=> 'boolean',
			'policy'		=> 'policy',
			},
			'peer'		=> {
			'exchange_mode' 	=> 'phase1_exchange_mode',
			'encryption_algorithm' 	=> 'phase1_encryption',
			'hash_algorithm' 	=> 'hash_algorithm',
			'dh_group'		=> 'dh_group',
			'authentication_method'	=> 'phase1_auth_method',
			'remote_template'	=> 'template_name',
			'lifetime'		=> 'lifetime',
			'verify_identifier'	=> 'switch',
			'verify_cert'		=> 'switch',
			'passive'		=> 'switch',
			'generate_policy'	=> 'switch',
			'initial_contact'	=> 'switch',
			'send_cr'		=> 'switch',
			'send_cert'		=> 'switch',
			'support_mip6'		=> 'switch',
			'my_identifier'		=> 'identifier',
			'peers_identifier'	=> 'identifier',
			'certificate_type'	=> 'certificate',
			'peers_certfile'	=> 'peers_certfile',
			'nonce_size'		=> 'nonce_size',
			'proposal_check'	=> 'proposal_check',
			'nat_traversal'		=> 'nat_traversal'
			},
			'global'		=> {
			'racoon_command'	=> 'shell_command',
			'racoon_pid_file'	=> 'path_generated_file',
			'path_pre_shared_key'	=> 'path_conf_file',
			'path_racoon_conf'	=> 'path_generated_file',
			'path_certificate'	=> 'path_certificate',
			'path_script'		=> 'path_script',
			'privsep'		=> 'boolean',
			'privsep_chroot'	=> 'path_chroot_dir',
			'privsep_user'		=> 'user',
			'privsep_group'		=> 'group',
			'log'			=> 'log',
			'listen'		=> 'listen',
			'complex_bundle'	=> 'switch'
			}
			);

my %prop_syntaxhash = (	'range'		=> '{ip-address|ip-address/masklen|ip-address[port]|ip-address/masklen[port]}',
			'ip'		=> '{ip-address} - IPv4 or IPv6',
			'port'		=> '{[any]|[port]} - any or port number, []s required',
			'uppserspec'	=> '{protocol} - number or from /etc/protocols or any or icmp6',
			'encap'		=> '{ah|esp}',
			'mode'		=> '{tunnel|transport}',
			'boolean'	=> '{enabled|disabled|true|false|yes|no|up|down|on|off|0|1}',
			'template_name'	=> '{template-name} - can be %default or ^[-a-zA-Z0-9_]+',
			'level'		=> '{default|use|require|unique}',
			'phase1_exchange_mode' 	=> '{main|aggressive|base}',
			'phase1_encryption'	=> '{des|3des|blowfish|cast128|aes|camellia}',
			'hash_algorithm'	=> '{md5|sha1|sha256|sha384|sha512}',
			'dh_group'		=> '{modp768|modp1024|modp1536|modp2048|modp3072|modp4096|modp6144|modp8192|1|2|5|14|15|16|17|18}',
			'pfs_group'		=> '{none|modp768|modp1024|modp1536|modp2048|modp3072|modp4096|modp6144|modp8192|1|2|5|14|15|16|17|18}',
			'phase1_auth_method'	=> '{pre_shared_key|rsasig}',
			'switch'		=> '{on|off}',
			'lifetime'		=> '{time} {integer} {hour|hours|min|mins|minutes|sec|secs|seconds}',
			'phase2_encryption'	=> '{des|3des|des_iv64|des_iv32|rc5|rc4|idea|3idea|cast128|blowfish|null_enc|twofish|rijndael|aes|camellia}',
			'phase2_auth_algorithm'	=> '{des|3des|des_iv64|des_iv32|hmac_md5|hmac_sha1|hmac_sha256|hmac_sha384|hmac_sha512|non_auth}',
			'identifier'		=> '{address [ip-address]|fqdn dns-name|user_fqdn user@dns-name|keyid file-name|asn1dn [asn1-name]}',
			'certificate'		=> '{x509 cert-file privkey-file}',
			'peers_certfile'	=> '{x509 cert-file|plain_rsa cert-file|dnssec}',
			'path_conf_file'	=> '{full-path-file-name}',
			'shell_command'		=> '{shell-command}',
			'path_generated_file'	=> '{full-path-file-name}',
			'path_certificate'	=> '{full-path-dir}',
			'path_script'		=> '{full-path-dir}',
			'log'			=> '{notify|debug|debug2}',
			'listen'		=> '{ip-address} [[port]]',
			'proposal_check'	=> '{obey|strict|claim|exact}',
			'nat_traversal'		=> '{on|off|force}',
			'nonce_size'		=> '{number} - between 8 and 256',
			'id_type'		=> '{address|subnet} - ID type of ISAKMP Phase II identifier',
			'policy'		=> '{discard|ipsec|none} - SPD policy',
			'path_chroot_dir'	=> '{full-path-chroot-dir} - racoon privsep chroot dir',
			'user'			=> '{system-user} - racoon privsep user',
			'group'			=> '{system-group} - racoon privsep group',

			);

my %bool_val = ( 	'enabled' => 1,
			'disabled' => 0,
			'true' => 1,
			'false'	=> 0,
			'yes' => 1,
			'no' => 0,
			'up' => 1,
			'down' => 0,
			'on' => 1,
			'off' => 0,
			'0' => 0,
			'1' =>1 );

# Default templates for spdadd and sadadd defined here
my $sadadd_default = "";
my $spdadd_default = <<'EOF';
spdadd ___src_range___ ___dst_range___ ___upperspec___ -P out ipsec
	___encap___/___mode___/___src_ip___-___dst_ip___/___level___;

spdadd ___dst_range___ ___src_range___ ___upperspec___ -P in ipsec
	___encap___/___mode___/___dst_ip___-___src_ip___/___level___;

EOF
my $spdadd_alternate_policy = <<'EOF';
spdadd ___src_range___ ___dst_range___ ___upperspec___ -P out ___policy___;

spdadd ___dst_range___ ___src_range___ ___upperspec___ -P in ___policy___;

EOF
%spdadd_addons = (	'ipcomp_in'	=> '	ipcomp/___mode___/___dst_ip___-___src_ip___/use',
			'ipcomp_out'	=> '	ipcomp/___mode___/___src_ip___-___dst_ip___/use',
			'ah_in'		=> '	ah/transport/___dst_ip___-___src_ip___/___level___',
			'ah_out'		=> '	ah/transport/___src_ip___-___dst_ip___/___level___'
		);
# allow the following icmp control traffic
# - echo reply (0)
# - destination unreachable (3)
# - source quench (4)
# - echo request (8)
# - time exceeded (11)
my $spdadd_ip4_header = << 'EOF';
spdadd ___src_subnet___ ___dst_subnet___ icmp -P out priority 1 none;

spdadd ___dst_subnet___ ___src_subnet___ icmp -P in priority 1 none;

EOF

my $spdadd_ip6_header = << 'EOF';
spdadd ___src_subnet___ ___dst_subnet___ icmp6 -P out priority 1 none;

spdadd ___dst_subnet___ ___src_subnet___ icmp6 -P in priority 1 none;

EOF

my $spdadd_transport_ip4_default = "$spdadd_ip4_header" . "$spdadd_default"; 

my $spdadd_transport_ip6_default = "$spdadd_ip6_header" . "$spdadd_default"; 

my $racoon_init_default = <<"EOF";
path script ___path_script___;
path pre_shared_key ___path_pre_shared_key___;
path certificate ___path_certificate___;

EOF
%init_addons = ('log'		=> 'log ___log___;',
		'listen' 	=> "listen {\n\tstrict_address;\n}",
		'isakmp' 	=> 'isakmp ___listen___;',
		'complex_bundle' => 'complex_bundle ___complex_bundle___;'
		);

my $racoon_privsep = <<'EOF';
privsep {
        chroot ___privsep_chroot___;
        user   ___privsep_user___;
        group  ___privsep_group___;
}

EOF

my $remote_default = <<'EOF';
remote ___dst_ip___ {
        exchange_mode ___exchange_mode___;
}

EOF
my $remote_proposal = <<'EOF';
        proposal {
                encryption_algorithm ___encryption_algorithm___;
                hash_algorithm ___hash_algorithm___;
                authentication_method ___authentication_method___;
                dh_group ___dh_group___;
        }
EOF

%remote_addons = ( 	'verify_identifier' 	=> 'verify_identifier ___verify_identifier___;',
			'verify_cert'		=> 'verify_cert ___verify_cert___;',
			'passive'		=> 'passive ___passive___;',
			'generate_policy'	=> 'generate_policy ___generate_policy___;',
			'my_identifier'		=> 'my_identifier ___my_identifier___;',
			'peers_identifier'	=> 'peers_identifier ___peers_identifier___;',
			'peers_certfile'	=> 'peers_certfile ___peers_certfile___;',
			'certificate_type'	=> 'certificate_type ___certificate_type___;',
			'lifetime'		=> 'lifetime ___lifetime___;',
			'initial_contact'	=> 'initial_contact ___initial_contact___;',
			'send_cr'		=> 'send_cr ___send_cr___;',
			'send_cert'		=> 'send_cert ___send_cert___;',
			'support_mip6'		=> 'support_mip6 ___support_mip6___;',
			'nonce_size'		=> 'nonce_size ___nonce_size___;',
			'proposal_check'	=> 'proposal_check ___proposal_check___;',
			'nat_traversal'		=> 'nat_traversal ___nat_traversal___;'
		);

my $sainfo_default = <<'EOF';
sainfo ___id_type___ ___local_id___ ___upperspec___ ___id_type___ ___remote_id___ ___upperspec___ {
        encryption_algorithm ___encryption_algorithm___;
        authentication_algorithm ___authentication_algorithm___;
	compression_algorithm deflate;
}

EOF
%sainfo_addons = ( 	'pfs_group'	=> 'pfs_group ___pfs_group___;',
			'lifetime'	=> 'lifetime ___lifetime___;'
		);

@modules = ();
@modules_ipsec = ('ah4', 'esp4', 'ipcomp');
@modules_ipsec6 = ('ah6', 'esp6', 'ipcomp6');

# Make stdout and stderr unbuffered
select STDERR;
$| = 1;
select STDOUT;
$| = 1;

# Make sure we are running as root
if ( $> != 0 ) {
	print STDERR "$progname: must be root to run this.\n";
	exit 1;
}

# 'Open' syslog
openlog ($progname, 'pid', 'daemon');

# Handle logging backend if '-l' switch given
log_backend ();

# See if we are already running...
check_if_running();

mod_ls();

parse_config();

$have_1arg = "vpndown|vpnup|vpnreload|vpnlist|vpnmenu|vdown|vup|vreload|vlist|vmenu";

# Process command line...
foreach my $i ( 0..$#ARGV ) {
	$ARGV[$i] = lc $ARGV[$i];
}

SWITCH: {
	!defined $ARGV[0] && do {
		usage ();
		exit 1;
	};
	$ARGV[0] =~ /^(${have_1arg})$/ && @ARGV > 2 && do {
		usage ();
		exit 1;
	};
	$ARGV[0] !~ /^(${have_1arg})$/ && @ARGV > 1 && do {
		usage ();
		exit 1;
	};

	$ARGV[0] =~ /^start$/ && do {

		ipsec_start ();

		last SWITCH;
	};
	$ARGV[0] =~ /^stop$/ && do {

		ipsec_stop ();

		last SWITCH;
	};
	$ARGV[0] =~ /^reload$/ && do {

		ipsec_load ();

		last SWITCH;
	};
	$ARGV[0] =~ /^(restart|force-reload)$/ && do {

		ipsec_stop ();

		@modules = ();
		ipsec_start ();

		last SWITCH;
	};

	$ARGV[0] =~ /^(sadshow|saddump|dump)$/ && do {
		# Show the SAD
		sad_show ();
		last SWITCH;
	};
	$ARGV[0] =~ /^(spdshow|spddump)$/ && do {
		# Show the SPD
		spd_show ();
		last SWITCH;
	};

	$ARGV[0] =~ /^(sadflush|flush)$/ && do {

		# Flush the SAD
		print "Flushing SAD...\n";
		sad_flush ();
		print "SAD flushed.\n";
		prog_warn 'info', "manually flushed SAD";

		last SWITCH;
	};

	$ARGV[0] =~ /^spdflush$/ && do {

		# Flush the SPD
		print "Flushing SPD...\n";
		spd_flush ();
		print "SPD flushed.\n";
		prog_warn 'info', "manually flushed SPD";

		last SWITCH;
	};

	$ARGV[0] =~ /^(vpndown|vdown)$/ && do {
		
		# Go and do it
		conn_down_handle ($ARGV[1]);
	
		last SWITCH;
	};
	
	$ARGV[0] =~ /^(vpnmenu|vmenu)$/ && do {
		
		# Go and do it
		conn_menu ($ARGV[1]);
	
		last SWITCH;
	};


	$ARGV[0] =~ /^(vpnup|vup)$/ && do {
		
		# Go and do it
		conn_up_handle ($ARGV[1]);
	
		last SWITCH;
	};

	$ARGV[0] =~ /^(vpnreload|vreload)$/ && do {
		
		# Go and do it
		conn_reload_handle ($ARGV[1]);
	
		last SWITCH;
	};

	$ARGV[0] =~ /^(vpnlist|vlist)$/ && do {
		
		# Go and do it
		conn_list ($ARGV[1]);
	
		last SWITCH;
	};

	$ARGV[0] =~ /^(racoonstart|rstart)$/ && do {
		
		# Go and do it
		racoon_start();
	
		last SWITCH;
	};

	$ARGV[0] =~ /^(racoonstop|rstop)$/ && do {
		
		# Go and do it
		racoon_stop();
	
		last SWITCH;
	};

	usage ();
	exit 1;
};

exit 0;

# Functions start here

sub usage () {
	print STDERR "\n";
	print STDERR "  Usage: $progname [-h] sadflush|spdflush|saddump|spddump\n";
	print STDERR "                              |reload|restart|force-reload|start|stop\n";
	print STDERR "         $progname [-h] vpndown|vdown|vpnup|vup\n";
	print STDERR "                              |vpnreload|vreload connection-name|all\n";
	print STDERR "         $progname [-h] vpnlist|vlist [connection-name|all]\n";
	print STDERR "         $progname [-h] vpnmenu|vmenu\n";
	print STDERR "         $progname [-h] racoonstart|racoonstop|rstart|rstop\n";
	print STDERR "\n";
};

sub basename ($$) {
	my $name = shift;
	my $ext = shift;
	$name =~ s/^.*\/(.*)$/$1/;
	$name =~ s/^(.*)${ext}$/$1/;
	return $name;
}

sub dirname ($) {
	my $name = shift;
	if ( $name eq '/' ) {
		return $name;
	}
	$name =~ s/^(.*)\/(.*)$/$1/;
	return $name;
}

sub openlog ($$$) {
	$log{'ident'} = shift;
	$log{'logopt'} = shift;
	$log{'facility'} = shift;
	my $logger;

	$logger = "/usr/bin/logger";
	if ( ! -x $logger ) {
		$logger = "/bin/logger";
	} elsif ( ! -x $logger ) {
		die "$progname: cannot run $logger.\n";
	}
	
	$log{'logger'} = $logger;

}

sub syslog ($$) {
	my $priority = shift;
	my $msg = shift; 

	system("$log{'logger'}", '-p', "$log{'facility'}.${priority}", '-t', "$log{'ident'}\[${proc_id}\]", "$msg");
}

sub check_if_running () {
        my @pids = ();
        my @procs = grep /\b${progname}$/, (grep ! /^\s*${proc_id}\b/, `$ps_cmd`);
        foreach (@procs) {
                my @fields = split;
                if (!$fields[0]) {
                        next;
                }
                push @pids, $fields[0];
        }
 
        if (@pids) {
                print STDERR "$progname: process(es) @pids are already running.\n";
                exit 2;
        }
}

sub racoon_get_pids () {
	my @pids = (); 
	my $cmd = '';
	my $pid_file = $global{'racoon_pid_file'};
	
	$cmd = $global{'racoon_command'};
	if ( $cmd =~ m/^(\S+).*$/ ) {
		$cmd = $1;
	}

	if ( -f $pid_file ) {
		if ( ! open PID, "$pid_file" ) {
			prog_die "cannot open $pid_file - $!";
		}
		@pids = ( <PID> );
		close PID;
	} elsif ( scalar(@pids = grep m#${cmd}[\s\n]#s, (split /^/m, `$psf_cmd`)) ) {
		grep { s/^\s*([0-9]+)\s+.*$/$1/; } @pids;
	} 
	
	return @pids;
}


sub racoon_fill_command ($) {
	my $stuff = shift;
	foreach my $key (keys %global) {
		my $key_reg = $key;
		$key_reg =~ s/\[/\\[/g;
		$key_reg =~ s/\]/\\]/g;
		$stuff =~ s/___${key_reg}___/$global{"$key"}/img;
	}
	return $stuff;
}

sub racoon_start () {
	my $running;
	my @pids = ();

	print "Starting IKE (ISAKMP/Oakley) server: ";
	
	# see if it is already running
	@pids = racoon_get_pids();
	
	if ( $running = kill ( '0', @pids ) ) {
		prog_warn 'warning', "racoon already running - exiting.", $fmt{'brief'};
		exit 10;
	}

	# Start it.
	my $stuff = racoon_fill_command ($global{'racoon_command'});
	system "$stuff";
	
	# See if it started	
	@pids = racoon_get_pids();
	$running = @pids;
	if ( ! $running ) {
		prog_die "racoon did not start.";
	}

	print "racoon.\n";
	prog_warn 'info', "racoon started.";
}

sub racoon_stop () {
	my @pids = ();
	my $running;
	
	print "Stopping IKE (ISAKMP/Oakley) server: ";

	# Find PIDs to use
	@pids = racoon_get_pids();
		
	# see if it is running
	$running = kill ('0', @pids );
	if ( ! $running ) {
		print "not found running.\n";
		return;
	}

	# kill -15 it
	$running = kill ( 'TERM', @pids );

        my $delay = $racoon_kill_delay;
	# Check if any still running
	while ( ($running = kill ( '0', @pids )) && $delay) {
		sleep 1;
	        $delay--;
		# see if still running, and loop back to wait upto 25 secs
	}

	# kill -9 it
	kill ( 'KILL', @pids );

	print "racoon.\n";
	prog_warn 'info', "racoon stopped.";
}

sub racoon_configure (;$) {
	my $format = shift;
	my @pids;
	my @new;
	my $running = 0;

	# Prepare new config file
	racoon_write_config ($global{'path_racoon_conf'}, $format);

	# HUP racoon to reconfigure it
	@pids = racoon_get_pids();
	$running = @pids;

	sad_flush();
	kill ( 'HUP', @pids );
	@pids = racoon_get_pids();
	if ($running && @pids < 1 ) {
		prog_warn 'err', "reconfiguring racoon failed - racoon died, check system logs.", $format;
		return -1;
	} elsif ( ! $running && @pids < 1) {
		prog_warn 'warning', "racoon not running.", $format;
		return 0;
	}
	return 1;
}

sub racoon_fill_remote ($) {
	my $peer = shift;
	my $stuff;

	my $hndl = $peer_list{$peer};
	my $template = $hndl->{'remote_template'};
	$stuff = $remote{$template};
	if ( $template eq '%default' ) {
		foreach my $property ( keys %remote_addons ) {
			if (defined $hndl->{"$property"}) {
				$stuff =~ s/^(\s*remote.*{\s*)$/${1}\n\t${remote_addons{"$property"}}/m;
			}
		}
		my $pindexes = $hndl->{'pindexes'};
		foreach my $ind ( @$pindexes ) {
			my $to_add = $remote_proposal;
			$to_add =~ s/___(\S+)___/___$1\[$ind\]___/gm;
			$stuff =~ s/^(\s*remote.*{\s*)$/${1}\n${to_add}/m
		}
	}


	foreach my $key (keys %$hndl) {
		my $key_reg = $key;
		$key_reg =~ s/\[/\\[/g;
		$key_reg =~ s/\]/\\]/g;
		$stuff =~ s/___${key_reg}___/$$hndl{"$key"}/img;
	}

	if ($peer eq '%anonymous' && $template eq '%default' ) {
		$stuff =~ s/(remote\s+)\%anonymous/remote anonymous/
	}

	return $stuff;
}

sub racoon_fill_sainfo ($) {
	my $connection = shift;
	my $stuff;

	my $hndl = $connection_list{$connection};
	my $template = $hndl->{'sainfo_template'};
	$stuff = $sainfo{$template};
	if ( $template eq '%default' ) {
		foreach my $property ( keys %sainfo_addons ) {
			next if $property eq "pfs_group" &&
				defined $hndl->{'pfs_group'} && $hndl->{'pfs_group'} eq 'none';
			if ( defined $hndl->{"$property"} ) {
				$stuff =~ s/^(\s*sainfo.*)$/${1}\n\t${sainfo_addons{"$property"}}/m;
			}
		}
	}

	foreach my $key (keys %$hndl) {
		$stuff =~ s/___${key}___/$$hndl{$key}/img;
	}

	if ($connection eq '%anonymous' && $template eq '%default' ) {
		$stuff =~ s/sainfo.*{/sainfo anonymous {/
	}

	return $stuff;
}

sub racoon_fill_init () {
	my $stuff = $racoon_init;

	foreach my $key ( keys %global ) {
		$key =~ s/^(\S+)\[[-0-9_a-z]+\]$/$1/i;
		if ( defined $init_addons{"$key"} ) {
			$stuff =~ s/^(\s*path certificate.*)$/${1}\n${init_addons{"$key"}}/m;
		}
	}
	my @indexes = prop_get_indexes ( %global );
	foreach my $ind ( @indexes ) {
		my $to_add = $init_addons{'isakmp'};
		$to_add =~ s/___(\S+)___/___$1\[$ind\]___/gm;
		$stuff =~ s/^(\s*listen.*{\s*)$/${1}\n\t${to_add}/m
	}

	if ( $bool_val{ $global{'privsep'} } != 0 ) {
		$stuff = $stuff . $racoon_privsep;
	}

	foreach my $key (keys %global) {
		my $key_reg = $key;
		$key_reg =~ s/\[/\\[/g;
		$key_reg =~ s/\]/\\]/g;
		$stuff =~ s/___${key_reg}___/$global{"$key"}/img;
	}

	return $stuff;
}

sub racoon_write_config ($$) {
	my $file = shift;
	my $format = shift;
	my @spd_list;
	my %conn_spd_hash;
	my @remote_done = ();
	my @sainfo_done = ();

	parse_spd (@spd_list, %conn_spd_hash);

	open (RCF, ">$file")
		or prog_die "can't open $file - $!", $format;

	# Pretty print comments...
	my $hostname = `/bin/hostname`;
	my $date = scalar localtime;
	print RCF <<"EOF";
#
# Racoon configuration for $hostname
# Generated on $date by $progname
#

EOF
	# Print out the racoon header
	print RCF "#\n# Global items\n#\n";
	my $stuff = racoon_fill_init();
	print RCF $stuff;


	foreach my $connection ( keys %conn_spd_hash ) {
		my $stuff = '';
		my $hndl = $connection_list{$connection};

		print RCF "#\n# Connection $connection\n#\n";
		# print remote clauses needed...
		my $dst_ip = $hndl->{'dst_ip'};
		if ( ! grep { $dst_ip eq $_ } @remote_done ) {
			push @remote_done, $dst_ip;
			$stuff = racoon_fill_remote($dst_ip);
			print RCF $stuff;
		}

		my $id_string = $hndl->{'local_id'} . '_' . $hndl->{'remote_id'};
		if ( grep { $id_string eq $_ } @sainfo_done) {
			print RCF "# using sainfo above here\n\n";
			next;
		}
		push @sainfo_done, $id_string;
		# print sainfo clauses needed...
		$stuff = racoon_fill_sainfo($connection);
		print RCF $stuff;
	}

	# Handle anonymous connection
	my $hndl = $connection_list{'%anonymous'};
	my $phndl = $peer_list{'%anonymous'};

	if ( defined $hndl && $hndl
		&& defined $hndl->{'admin_status'}
		&& $bool_val{"$hndl->{'admin_status'}"} != 0
		&& $hndl->{'makelive'} != 0 
		&& defined $phndl
		&& $phndl
		&& $phndl->{'makelive'} != 0 ) {
		my $stuff = '';
		print RCF "#\n# Anonymous connection section\n#\n";
		$stuff = racoon_fill_remote('%anonymous');
		print RCF $stuff;
		$stuff = racoon_fill_sainfo('%anonymous');
		print RCF $stuff;
	}

	close RCF;
}

sub log_backend () {
	foreach my $arg ( @ARGV ) {
		next if $arg ne '-l';

		my $error = 0;
		while ( <STDIN> ) {
			chomp;
			prog_warn 0, "setkey said: $_";
			$error = 1;
		}

		exit $error;
	}
}

# List all connections
sub conn_list ($) {
	my $connection = shift;

	my $exit_code = 1;

	if ( ! defined $connection || $connection eq 'all' ) {
		$connection = '.*';
	}

	my @conns = grep /${connection}/, keys(%connection_list);
	@conns = grep !/^%default$/, @conns;
	open( PAGER, '|-' ) 
		|| exec ("$pager_cmd", @pager_flags);
	foreach my $conn ( @conns ) {
		print PAGER "$conn\n";
	}
	close PAGER or die "$progname: conn_list () - $pager_cmd failed - exit code " . ($? >> 8) . "\n";

	exit ( scalar(@conns) == 0 );
}

# Connection up
sub conn_up_handle ($) {
	my $connection = shift;

	if (! defined $connection ) {
		usage ();
		exit 1;
	}

	if ( $connection eq 'all' ) {
		# Flush SPD and SAD
		ipsec_flush ();
		
		# Load the SPD
		spd_load();

		# Do dee racoon...
		exit 1 if racoon_configure() < 0;

		exit 0;
	}

	print "Starting VPN $connection...";
	if ((my $ret = spd_load($connection)) <= 0 ) {
		print "not found in configuration\n" if $ret == 0;
		print "syntax problem in configuration.\n" if $ret == -1;
		print "already in SPD.\n" if $ret == -2;
		exit 1;
	}

	# Do dee racoon...
	exit 1 if racoon_configure($fmt{'brief'}) < 0;

	print "done.\n";
	prog_warn 'info', "$connection started.";


	exit 0;
}

# Connection down
sub conn_down_handle ($) {
	my $connection = shift;
	my @spd_list;
	my %conn_spd_hash;

	if ( ! defined $connection ) {
		usage ();
		exit 1;
	}

	if ( $connection eq 'all' ) {
		# Flush SPD and SAD
		ipsec_flush ();
		
		# Do dee racoon...
		exit 1 if racoon_configure() < 0;
		
		exit 0;
	}

	print "Shutting down VPN $connection...";
	if ( ! grep /^${connection}$/, keys %connection_list) {
		print "not found in configuration.\n";
		exit 1;
	}
	# Read SPD list from kernel...
	parse_spd(@spd_list, %conn_spd_hash);
	if ( ! conn_down (@spd_list, %conn_spd_hash, $connection, 1) ) {
		print "not found in SPD.\n";
		exit 0;
	}
	print "done.\n";
	prog_warn 'info', "$connection shutdown.";

	exit 0
}

sub conn_reload_handle ($) {
	my $connection = shift;
	my @spd_list;
	my %conn_spd_hash;

	if ( ! defined $connection ) {
		usage ();
		exit 1;
	}

	if ( $connection eq 'all' ) {
		ipsec_load();
		
		exit 0;
	}

	print "Reloading VPN $connection...";
	if ( ! grep /^${connection}$/, keys %connection_list) {
		print "not found in configuration.\n";
		exit 1;
	}
	# Read SPD list from kernel...
	parse_spd(@spd_list, %conn_spd_hash);
	if ( ! conn_down (@spd_list, %conn_spd_hash, $connection, 1, 1) ) {
		print "not found in SPD, ";
	}

	if ((my $ret = spd_load($connection)) <= 0 ) {
		print "not found in configuration.\n" if $ret == 0;
		print "syntax problem in configuration.\n" if $ret == -1;
		print "already in SPD.\n" if $ret == -2;
		exit 1;
	}

	# Do dee racoon...
	exit 1 if racoon_configure($fmt{'brief'}) < 0;

	print "done.\n";
	prog_warn 'info', "$connection reloaded.";

	exit 0;
}

sub spd_show_header () {
	print "Number  Connection Name                                     UpperSpec  DirN\n";
	print "          src_range\n";
	print "          dst_range\n";
	print "          policy\n";
}

sub spd_show_entry ($) {
	my $entry = shift;
	my $conn_name;

	if (defined $$entry{'connection'}) {
		$conn_name = $$entry{'connection'};
	} else {
		$conn_name = '';
	}

	printf "   %3.1d  %-50s  %-9s  %-3s\n", 
		$$entry{'index'}, $conn_name, 
		$$entry{'upperspec'}, $$entry{'direction'};
	print "          $$entry{'src_range'}\n";
	print "          $$entry{'dst_range'}\n";
	print "          $$entry{'policy'}\n";
}

sub spd_show_footer () {
	print "\n";
	print "Press <Return> for more, or enter number or VPN-name > ";
}

sub conn_menu ($) {
	my $term = shift;
	my @spd_list;
	my %conn_spd_hash;

	# Initialise the SPD data structure
	parse_spd(@spd_list, %conn_spd_hash);
	# Reverse dirN for better human recongition so that it is in config file order
	@spd_list = reverse @spd_list;

	my ($pos,$rows,$cols,$do_fill) = 0;
	$term = '.*' if ! defined $term;
	my @spd = grep { ( defined $$_{'connection'} && $$_{'connection'} =~ m/${term}/ )
				|| $$_{'src_range'} =~ m/${term}/
				|| $$_{'dst_range'} =~ m/${term}/ } @spd_list;

	if ( ! @spd ) {
		print "No SPD entries found.\n";
		return;
	}

REDRAW:	while ($pos < @spd_list) {
		# get terminal size 
		($rows, $cols) = split ' ', `stty size`;
		my $ntoshow = ($rows - 7) / 4;
		my $fill = $rows % $ntoshow;
		if ( ($pos +$ntoshow)  > @spd) {
			$fill += 4*($pos + $ntoshow - @spd);
		}
		# display SPD list
		if ( $do_fill ) {
			foreach (0..$fill) { print "\n" };
		}
		$do_fill = 1;
		spd_show_header ();
		for ($i=$pos; $i < ($pos + $ntoshow) && $i < @spd; $i++) {

			spd_show_entry ($spd[$i]);
		}
		spd_show_footer ();

		# wait for keypress
		while ( my $chars = <STDIN> ) {
			last if $chars =~ /^$/;
			$chars = lc $chars;
			exit 0 if $chars =~ /^q$/;
			chomp $chars;
			my @deleted = conn_down(@spd_list, %conn_spd_hash, $chars) if $chars =~ /^[-0-9a-z_]+$/;
			if (! @deleted) {
				print "$chars does not exist or cannot be deleted.\n";
			} 
			else {	
				foreach my $i ( @deleted ) {
					@spd = grep { $i != $$_{'index'} } @spd;				
					$pos -= 1 if $pos > 0;
				}
			}
			if ( ! @spd ) {
				print "No selected SPD entries left.\n";
				last REDRAW;
			}
			sleep 2;
			next REDRAW;
		}

		$pos += $ntoshow;
	}


}

sub conn_down (\@\%$;$$) {
	my $spd_list = shift;
	my $conn_spd_hash = shift;
	my $spd = shift;
	my $conn_force = shift;
	my $no_racoon = shift;

	my @ret = ();
	my @spd_to_del = ();
	if ( $conn_force || $spd !~ m/^[0-9]+$/ ) {
		# Deal with a connection name
		@spd_to_del = keys %$conn_spd_hash;
		return @ret if @spd_to_del <= 0;
		return @ret if ! grep /^$spd$/, keys %$conn_spd_hash;
		@spd_to_del = @{ $conn_spd_hash->{$spd} };
		return @ret if @spd_to_del <= 0; 
	} 
	else {
		# Handle a connection number
		# Check that it exists
		return @ret if ! grep { $$_{'index'} == $spd } @$spd_list;

		# Follow up any connection name and add that one to
		my ($spdentry) = grep { $$_{'index'} == $spd }  @$spd_list;
		goto GO if ! defined $$spdentry{'connection'};
		$connection = $$spdentry{'connection'};
		goto GO if @{ $conn_spd_hash->{$connection} } <= 0;
		push @spd_to_del, @{ $conn_spd_hash->{$connection} };
	}

GO:
	# Delete entries from SPD
	open( SETKEY, '|-')
		|| exec ("$setkey_cmd", '-f', '/dev/stdin');

	foreach my $spdnum ( @spd_to_del ) {
		my ($spdentry) = grep { $$_{'index'} == $spdnum }  @$spd_list;
	print SETKEY <<"EOF";
spddelete -n $$spdentry{'src_range'} $$spdentry{'dst_range'} $$spdentry{'upperspec'} -P $$spdentry{'direction'};
EOF
		push @ret, $spdnum;
	}

	close SETKEY
		or prog_die ("conn_down() - setkey connection deletion failed - exit code ". ($? >> 8) );

	sleep($quiesce) if ($quiesce > 0);
	# Deal with racoon
	if ( ! $no_racoon ) {
		racoon_configure();
	}

	return @ret;
}

# Process warning message

sub prog_warn($$;$) {
	my $level = shift;
	my $msg = shift;
	my $format = shift;

	$format = $global_format if ! $format;
	$level = 'warning' if ! $level;
	$msg =~ s/\t/        /g;
	if ( $level ne 'info' ) {
		if ( $format == $fmt{'normal'} ) { 
			print STDERR "$progname: $msg\n"
		} elsif ( $format == $fmt{'brief'} ) {
			print STDOUT "${msg}\n";
		} elsif ( $format == $fmt{'comma'} ) {
			$msg =~ s/\.$//;
			print STDOUT "${msg}, ";
		}
	}
	$msg =~ s/%/%%/g;
	syslog ($level, "$msg");
}

sub prog_die($;$) {
	my $msg = shift;
	my $format = shift;
	prog_warn 'err', $msg, $format;
	exit 255;
}

# Dump read in SPD list
sub spd_dump_list (\@\%) {
	my $spd_list = shift;
	my $conn_spd_hash = shift;

	for my $spd ( @$spd_list ) {
		print "{ ";
		for $val ( keys %$spd ) {
			print "$val=$spd->{$val} ";
		}
		print "}\n";
	}

	for my $conn ( keys(%$conn_spd_hash) ) {
		print "$conn: @{ $conn_spd_hash->{$conn} }\n";
	}
}

# Parse SPD to produce SPD list
sub parse_spd (\@\%) {
	my $spd_list = shift;
	my $conn_spd_hash = shift;
	my $src_range;
	my $dst_range;
	my $upperspec;
	my $direction;
	my $onespd_flag = 0;

	@$spd_list = ();

	open (SETKEY, '-|')
		|| exec ($setkey_cmd, '-PD');

	while (my $line = <SETKEY>) {
		# print "$line";
		if ( $line =~ m/^\s*([0-9a-fny\.\:\/\[\]]+)\s+([0-9a-fny\.\:\/\[\]]+)\s+([-0-9a-z]+)\s*$/ ){
			$src_range = $1;
			$dst_range = $2;
			$upperspec = $3;
			# For Linux
			$upperspec = 'any' if ($upperspec eq '255');
			$onespd_flag = 1
		} 
		elsif ($onespd_flag > 0) {
			$onespd_flag = 0;
			$line =~ m/^\s*(in|out|fwd)\s+(prio)?.*\s?(ipsec|none|discard)\s*$/;
			$direction = $1;
			$policy = $3;
			push @$spd_list, { 'src_range', $src_range, 'dst_range', $dst_range, 
					'upperspec', $upperspec, 'direction', $direction, 'policy', $policy };
			# print "[ src_range=$src_range, dst_range=$dst_range, upperspec=$upperspec, direction=$direction ]\n";
		}
	}

	close (SETKEY)
		or prog_die "parse_spd() - can't parse SPD - exit code " . ($? >> 8);
	# match the SPD policies to configuration data.
	match_spd_connection (@$spd_list, %$conn_spd_hash);

}


sub match_spd_connection (\@\%) {
	my $spd_list = shift;
	my $conn_spd_hash = shift;
	my $index = 0;

	%$conn_spd_hash = ();

	foreach my $spd ( @$spd_list ) {
		$spd->{'index'} = $index;
		
		# Loop over connection list to find connection name
		foreach my $connection ( keys %connection_list ) {
			next if "$connection" eq '%default';
			next if ! defined $connection_list{$connection}{'src_ip'};
			next if ! defined $connection_list{$connection}{'dst_ip'};
			
			# Quick handle - read only
			my $chndl = $connection_list{$connection};
			# Below covers ipsec and none
			my $pindexes = $chndl->{'pindexes'};
			foreach my $ind (@$pindexes) {
				if ($spd->{'upperspec'} eq $chndl->{'upperspec'}
					  && $spd->{'src_range' } eq $chndl->{"src_range[${ind}]"}
					  && $spd->{'dst_range'} eq $chndl->{"dst_range[${ind}]"}
					  && $spd->{'direction'} eq 'out'
					|| $spd->{'upperspec'} eq $chndl->{'upperspec'}
					  && $spd->{'dst_range'} eq $chndl->{"src_range[${ind}]"}
					  && $spd->{'src_range'} eq $chndl->{"dst_range[${ind}]"}
					  && $spd->{'direction'} eq 'in'
					|| $spd->{'upperspec'} eq $chndl->{'upperspec'} 
					  && $spd->{'dst_range'} eq $chndl->{"src_range[${ind}]"}
					  && $spd->{'src_range'} eq $chndl->{"dst_range[${ind}]"}
					  && $spd->{'direction'} eq 'fwd') {
					$spd->{'connection'} = $connection;
					push @{ $conn_spd_hash->{$connection} }, $index;
				}
			}	
			# Match for non-multi SPD connections
			if ($spd->{'upperspec'} eq $chndl->{'upperspec'}
				  && $spd->{'src_range' } eq $chndl->{'src_range'}
				  && $spd->{'dst_range'} eq $chndl->{'dst_range'}
				  && $spd->{'direction'} eq 'out'
				|| $spd->{'upperspec'} eq $chndl->{'upperspec'}
				  && $spd->{'dst_range'} eq $chndl->{'src_range'}
				  && $spd->{'src_range'} eq $chndl->{'dst_range'}
				  && $spd->{'direction'} eq 'in'
				|| $spd->{'upperspec'} eq $chndl->{'upperspec'} 
				  && $spd->{'dst_range'} eq $chndl->{'src_range'}
				  && $spd->{'src_range'} eq $chndl->{'dst_range'}
				  && $spd->{'direction'} eq 'fwd'
				|| $spd->{'src_range' } eq $chndl->{'src_subnet'}
				  && $spd->{'dst_range'} eq $chndl->{'dst_subnet'}
				  && $spd->{'direction'} eq 'out'
				  && $spd->{'policy'} =~ m/^(none|discard)$/ 
				||  $spd->{'dst_range'} eq $chndl->{'src_subnet'}
				  && $spd->{'src_range'} eq $chndl->{'dst_subnet'}
				  && $spd->{'direction'} eq 'in'
				  && $spd->{'policy'} =~ m/^(none|discard)$/ 
				|| $spd->{'dst_range'} eq $chndl->{'src_subnet'}
				  && $spd->{'src_range'} eq $chndl->{'dst_subnet'}
				  && $spd->{'direction'} eq 'fwd'
				  && $spd->{'policy'} =~ m/^(none|discard)$/){
				$spd->{'connection'} = $connection;
				push @{ $conn_spd_hash->{$connection} }, $index;
			}
		}

		$index ++;
	}

}

# start 
sub ipsec_start () {
	mod_start ();
	ipsec_flush ();
	ipsec_load ();
	racoon_start();
}

# stop
sub ipsec_stop () {
	racoon_stop();
	ipsec_flush ();
	mod_stop ();
}

# load
sub ipsec_load () {
	print "Loading SAD and SPD...\n";
	sad_init ();
	spd_init ();
	spd_load();
	print "SAD and SPD loaded.\n";
	prog_warn 'info', "loaded SAD and SPD.";
	print "Configuring racoon...";
	exit 1 if racoon_configure($fmt{'brief'}) < 0;
	print "done.\n";
	prog_warn 'info', "configured racoon.";
	return 1;
}

# flush 
sub ipsec_flush () {
	print "Flushing SAD and SPD...\n";
	# Flush the SAD
	sad_flush ();

	# Flush the SPD
	spd_flush ();
	print "SAD and SPD flushed.\n";
	prog_warn 'info', "flushed SAD and SPD.";
}

# Read configuration
sub parse_config () {
	my $line = 0;
	my $barf = 0;
	my $section = "";
	my $connection = "";
	my $peer = "";
	my $stuff = "";
	my $name = "";
	my @conffiles = ();

	if (-e  "$conffiledir") {
		opendir(CONFDIR, $conffiledir) || prog_die "can't open $conffiledir - $!";
		@conffiles = grep { not /^\.{1,2}\z/ or /^.*\.conf$/ } readdir(CONFDIR);
		@conffiles = map { $conffiledir . '/' . $_ } @conffiles;
		closedir CONFDIR;
	}
	unshift @conffiles, $conffile;

	CF: for my $cf (@conffiles) {

		# next CF if ( not -r $cf );

		open(CONF, "< $cf")
			|| prog_die "can't open $cf - $!";
																      
		LINE: while (<CONF>) {
			$line +=1;
																      
			# Deal with blank lines
			if ( m/^\s*$/) {
				next LINE;
			}
																      
			# Comments
			if ( m/^[ \t]*#.*$/ ) {
				next LINE;
			}
			# Comments at the end of lines
			if ( m/^([^#]*)#.*$/ ) {
				$_ = $1;
			}
																      
			chomp;

			if (! m/^[-\"{}()\[\]_;\%\@\w\s.:\/=]+$/) {
				prog_warn 0, "bad data in $cf, line $line:";
				prog_warn 0, $_;
				# $barf = 1;
				next LINE;
			}
			
			if ( m/^\s*SPDADD\((\%default|[-_a-z0-9]+)\):([\S \t]*)$/i ) {
				$name = $1;
				$stuff = $2 . "\n";
				if ( defined $spdadd{"$name"} ) {
					$spdadd{"$name"} .= $stuff;
				} else {
					$spdadd{"$name"} = $stuff;
				}
				next LINE;
			} elsif ( m/^\s*SPDADD_TRANSPORT_IP4\((\%transport_ip4_default|[-_a-z0-9]+)\):([\S \t]*)$/i ) {
				$name = $1;
				$stuff = $2 . "\n";
				if ( defined $spdadd{"$name"} ) {
					$spdadd{"$name"} .= $stuff;
				} else {
					$spdadd{"$name"} = $stuff;
				}
				next LINE;
			} elsif ( m/^\s*SPDADD_TRANSPORT_IP6\((\%transport_ip6_default|[-_a-z0-9]+)\):([\S \t]*)$/i ) {
				$name = $1;
				$stuff = $2 . "\n";
				if ( defined $spdadd{"$name"} ) {
					$spdadd{"$name"} .= $stuff;
				} else {
					$spdadd{"$name"} = $stuff;
				}
				next LINE;
			} elsif ( m/^\s*SADADD\((\%default|[-_a-z0-9]+)\):([\S \t]*)$/i ) {
				$name = $1;
				$stuff = $2 . "\n";
				if ( defined $sadadd{"$name"} ) {
					$sadadd{"$name" } .= $stuff;
				} else {
					$sadadd{"$name"} = $stuff;
				}
				next LINE;
			} elsif ( m/^\s*REMOTE\((\%default|[-_a-z0-9]+)\):([\S \t]*)$/i ) {
				$name = $1;
				$stuff = $2 . "\n";
				if ( defined $remote{"$name"} ) {
					$remote{"$name" } .= $stuff;
				} else {
					$remote{"$name"} = $stuff;
				}
				next LINE;

			} elsif ( m/^\s*SAINFO\((\%default|[-_a-z0-9]+)\):([\S \t]*)$/i ) {
				$name = $1;
				$stuff = $2 . "\n";
				if ( defined $sainfo{"$name"} ) {
					$sainfo{"$name" } .= $stuff;
				} else {
					$sainfo{"$name"} = $stuff;
				}
				next LINE;

			} elsif ( m/^\s*SADINIT:([\S \t]*)$/i ) {
				$name = '';
				$stuff = $1 . "\n";
				if ( defined $sadinit ) {
					$sadinit .= $stuff;
				} else {
					$sadinit = $stuff;
				}
				next LINE;
			} elsif ( m/^\s*SPDINIT:([\S \t]*)$/i ) {
				$name = '';
				$stuff = $1 . "\n";
				if ( defined $spdinit ) {
					$spdinit .= $stuff;
				} else {
					$spdinit = $stuff;
				}
				next LINE;
			} elsif ( m/^\s*RACOONINIT:([\S \t]*)$/i ) {
				$name = '';
				$stuff = $1 . "\n";
				if ( defined $racoon_init ) {
					$racoon_init .= $stuff;
				} else {
					$racoon_init = $stuff;
				}
				next LINE;

			} elsif ( m/^\s*CONNECTION\((\%default|\%anonymous|[-_a-z0-9]+)\):\s*$/i ) {
				$section = 'connection';
				$connection = lc $1;
				# Make place holder so that error message gets generated
				$connection_list{$connection}{'makelive'} = 0;
				next LINE;
			} 

			elsif ( m/^\s*PEER\((\%default|\%anonymous|[a-f0-9:\.]+)\):\s*$/i ) {
				$peer = lc $1;
				if ( $peer ne '%default' && $peer ne '%anonymous' && ! ip_check_syntax ($peer)) {
					prog_warn 0, "unrecognised tag in $cf, line $line:";
					prog_warn 0, "$_";
					prog_warn 0, "invalid peer name - $peer";
					next LINE;
				}
				$section = 'peer';
				# Make place holder so that error message gets generated
				$peer_list{$peer}{'makelive'} = 0;
				next LINE;
			}

			elsif  ( m/^\s*GLOBAL:\s*$/i ) {
				$section = 'global';
				next LINE;
			} 
		 
			elsif ( $section eq 'connection' &&  m/^\s*($conn_proplist):\s*(.+)\s*$/i ) {
				my $property = lc $1;
				my $value = $2;
				$value =~ s/^(.*\S)\s*$/$1/;
			
				if ( ! check_property_syntax($section, $property, $value) ) {
					prog_warn 0, "$connection - unrecognised connection property syntax.";
					prog_warn 0, "$connection - file $cf, line $line:";
					prog_warn 0, error_getmsg($section, $property);
					prog_warn 0, $_;
					$connection_list{$connection}{'syntax_error'} = 1;
					next LINE;
				}
				$value = value_lc($section, $property, $value);
				# Keep list of spd indexes for ordering
				prop_store_index(%{ $connection_list{$connection} }, $property);
				$connection_list{$connection}{$property} = $value; 
			} elsif ( $section eq 'connection' ) {
				prog_warn 0, "$connection - unrecognised tag in $cf, line $line:";
				prog_warn 0, $_;
				prog_warn 0, "$connection - allowed tags are $conn_proplist";
				$connection_list{$connection}{'syntax_error'} = 1;
				next LINE;
			}

			elsif ( $section eq 'peer' &&  m/^\s*($peer_proplist):\s*(.+)\s*$/i ) {
				my $property = lc $1;
				my $value = $2;
				$value =~ s/^(.*\S)\s*$/$1/;
			
				if ( ! check_property_syntax($section, $property, $value) ) {
					prog_warn 0, "$peer - unrecognised peer property syntax or unreadable file(s).";
					prog_warn 0, "$peer - file $cf, line $line:";
					prog_warn 0, error_getmsg($section, $property);
					prog_warn 0, $_;
					$peer_list{$peer}{'syntax_error'} = 1;
					next LINE;
				}
				# Keep list of proposal indexes for ordering
				prop_store_index(%{ $peer_list{$peer} }, $property);
				# $value = value_lc($section, $property, $value);
				$peer_list{$peer}{$property} = $value; 
			} elsif ( $section eq 'peer' ) {
				prog_warn 0, "$peer - unrecognised tag in $cf, line $line:";
				prog_warn 0, $_;
				prog_warn 0, "$peer - allowed tags are $peer_proplist";
				$peer_list{$peer}{'syntax_error'} = 1;
				next LINE;
			}

			elsif ( $section eq 'global' && m /^\s*($global_proplist):\s*(.+)\s*$/i ) {
				my $property = lc $1;
				my $value = $2;
				$value =~  s/^(.*\S)\s*$/$1/;
				
				if (! check_property_syntax($section, $property, $value)) {
					prog_warn 0, "global - unrecognised global property syntax, non existent user/group or unreadable file(s).";
					prog_warn 0, "global - file $cf, line $line:";
					prog_warn 0, error_getmsg($section, $property);
					prog_warn 0, $_;
					prog_warn 0, "global - allowed tags are $global_proplist";
					$global{'deadly_error'} = 1;
					next LINE;
				}
				$value = value_lc($section, $property, $value);
				$global{$property} = $value;

			} elsif ( $section eq 'global' ) {
				prog_warn 0, "$global - unrecognised tag in $cf, line $line:";
				prog_warn 0, $_;
				prog_warn 0, "$global - allowed tags are $global_proplist";
			}

			else {
				prog_warn 0, "unrecognised tag in $cf, line $line:";
				prog_warn 0, $_;
				next LINE;
			}
																      
		}
		close (CONF);
	}											      
	
	if ( $barf ) {
		exit 1;
	}
															      
	# apply defaults
	$spdadd{'%default'} = $spdadd_default if ( ! defined $spdadd{'%default'} );
	$spdadd{'%transport_ip4_default'} = $spdadd_transport_ip4_default if ( ! defined $spdadd{'%transport_ip4_default'} );
	$spdadd{'%transport_ip6_default'} = $spdadd_transport_ip6_default if ( ! defined $spdadd{'%transport_ip6_default'} );
	$sadadd{'%default'} = $sadadd_default if ( ! defined $sadadd{'%default'} );
	$remote{'%default'} = $remote_default if ( ! defined $remote{'%default'} );
	$sainfo{'%default'} = $sainfo_default if ( ! defined $sainfo{'%default'} );
	$racoon_init = $racoon_init_default if ( ! defined $racoon_init );
	global_fillin_defaults();
	conn_fillin_defaults();
	peer_fillin_defaults();
	peer_check_required();
	conn_check_required();
	global_check_required();
};

# Lower case value function
sub value_lc ($$$) {
	my $section = shift;
	my $property = shift;
	my $value = shift;

	my $ptype = get_proptype($section, $property);

	if ( $ptype eq 'path_conf_file' ) {
		$value = $value;
	} elsif ( $ptype eq 'path_generated_file' ) {
		$value = $value;
	} elsif ( $ptype eq 'path_chroot_dir' ) {
		$value = $value;
	} elsif ( $ptype eq 'user' ) {
		$value = $value;
	} elsif ( $ptype eq 'group' ) {
		$value = $value;
	} elsif ( $ptype eq 'shell_command' ) {
		$value = $value;
	} elsif ( $ptype eq 'path_certificate' ) {
		$value = $value;
	} elsif ( $ptype eq 'certificate' ) {
		if ( $value =~ m/^\s*x509\s+(\S+)\s+(\S+)\s*$/i ) {
			$value = "x509 $1 $2";
		}
	} elsif ( $ptype =~ 'peers_certfile' ) {
		if ( $value =~ m/^\s*dnssec\s*$/i ) {
			$value = "dnssec";
		} elsif ( $value =~ m/^\s*(plain_rsa|x509)\s+(\S+)\s*$/i ) {
			$value = "$1 $2";
		}
	} elsif ( $ptype eq 'identity' ) {
		if ( $value =~ m/^\s*keyid\s+(\S+)\s*$/i ) {
			$value = "keyid $1"
		}
	} else {
		$value = lc $value;
	}
	return $value;
}

# Error mesage lookups
sub error_getmsg ($$) {
	my $section = shift;
	my $property = shift;
	my $ptype = get_proptype($section, $property);

	return "$property only takes $prop_syntaxhash{$ptype}";
}

#Fill in global defaults
sub global_fillin_defaults () {
	foreach $prop ('path_pre_shared_key', 'path_certificate', 'path_script',
			'privsep_chroot', 'privsep_user', 'privsep_group' ) {
		if ( defined $global{$prop} && $global{$prop} =~ m/^"?(\S+)"?$/i ) {
			$global{$prop} = "\"${1}\"";
		}
	}
	foreach $prop ('path_racoon_conf', 'racoon_command', 'racoon_pid_file') {
		if ( defined $global{$prop} && $global{$prop} =~ m/^"(\S+)"$/i ) {
			$global{$prop} = "${1}";
		}
	}
}

sub global_check_required () {
	if ( $global{'deadly_error'} ) {
		prog_warn 'err', "deadly error in global configuration - exiting.";
		exit 10;
	}
}

#Check synax of IP address
sub ip_check_syntax ($) {
	my $ip = shift;
	if ( $ip =~ m/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/ ) {
		return 1 if ( $1 >=0 && $1 <= 255 && $2 >= 0 && $2 <= 255
			&& $3 >= 0 && $3 <= 255 && $4 >= 0 && $4 <= 255 );
	} elsif ( $ip =~ m/^[0-9a-f]{1,4}:[0-9a-f:]*:[0-9a-f]{0,4}$/i ) {
		my @dbytes = split  /:/, $ip;
		my $valid = 1;
		foreach my $v ( @dbytes ) {
			if ( $v ne '' && $v !~ m/^[0-9a-f]{1,4}$/i && $v < 0 && $v > 0xffff )
				{ $valid = 0; }
		}
		return 1 if $valid;
	}
	return 0;	
}


# Check syntax

sub get_proptype($$) {
	my $section = shift;
	my $property = shift;
	my $ptype;

	if ( $property =~ m/^(.*)\[[-_0-9a-z]+\]$/ ) {
		$property = $1;
	}
	$ptype = $prop_typehash{$section}{$property};	

	return $ptype;
}

sub check_property_syntax ($$$) {
	my $section = shift;
	my $property = shift;
	my $value = shift;
	my ($protoname, $protoaliases, $protonumber);
	my $ptype;

	$ptype = get_proptype($section,$property);

	if ( $ptype eq 'boolean' ) {
		$value =~ m/^(enabled|disabled|true|false|up|down|on|off|yes|no|0|1)$/i && return 1;
	} elsif ( $ptype eq 'id_type' ) {
		$value =~ m/^(address|subnet)$/i && return 1;
	} elsif ( $ptype eq 'encap' ) {
		$value =~ m/^(ah|esp)$/i && return 1;
	} elsif ( $ptype eq 'mode' ) {
		$value =~ m/^(transport|tunnel)$/i && return 1;
	} elsif ( $ptype eq 'template_name' ) {
		$value =~ m/^(%default|[-a-z0-9_]+)$/i && return 1;
	} elsif ( $ptype eq 'phase1_exchange_mode' ) {
		$value =~ m/^((main|aggressive|base),? ?){1,3}$/i && return 1;
	} elsif ( $ptype eq 'phase1_encryption' ) {
		$value =~ m/^(des|3des|blowfish|cast128|aes|camellia)$/i && return 1;
	} elsif ( $ptype eq 'hash_algorithm' ) {
		$value =~ m/^(md5|sha1|sha256|sha384|sha512)$/i && return 1;
	} elsif ( $ptype eq 'phase1_auth_method' ) {
		$value =~ m/^(pre_shared_key|rsasig)$/i && return 1;
	} elsif ( $ptype eq 'switch' ) {
		$value =~ m/^(on|off)$/i && return 1;
	} elsif ( $ptype eq 'lifetime' ) {
		$value =~ m/^time\s+[0-9]+\s+(hour|hours|min|mins|minutes|sec|secs|seconds)$/i && return 1;
	} elsif ( $ptype eq 'phase2_encryption' ) {
		$value =~ m/^((des|3des|des_iv64|des_iv32|rc5|rc4|idea|3idea|cast128|blowfish|null_enc|twofish|rijndael|aes|camellia),? ?)+$/i && return 1;
	} elsif ( $ptype eq 'phase2_auth_algorithm' ) {
		$value =~ m/^((des|3des|des_iv64|des_iv32|hmac_md5|hmac_sha1|hmac_sha256|hmac_sha384|hmac_sha512|non_auth),? ?)+$/i && return 1;
	} elsif ( $ptype eq 'dh_group' ) {
		$value =~ m/^(modp768|modp1024|modp1536|modp2048|modp3072|modp4096|modp6144|modp8192|1|2|5|14|15|16|17|18)$/i && return 1;
	} elsif ( $ptype eq 'pfs_group' ) {
		$value =~ m/^(none|modp768|modp1024|modp1536|modp2048|modp3072|modp4096|modp6144|modp8192|1|2|5|14|15|16|17|18)$/i && return 1;
	} elsif ( $ptype eq 'level') {
		$value =~ m/^(default|use|require|unique)$/i && return 1;
	} elsif ( $ptype eq 'log') {
		$value =~ m/^(notify|debug|debug2)$/i && return 1;
	} elsif ( $ptype eq 'proposal_check' ) {
		$value =~ m/^(obey|strict|claim|exact)$/i && return 1;
	} elsif ( $ptype eq 'nat_traversal' ) {
		$value =~ m/^(on|off|force)$/i && return 1;
	} elsif ( $ptype eq 'policy' ) { 
		$value =~ m/^(discard|ipsec|none)$/i && return 1;
	} elsif ( $ptype =~ 'nonce_size' ) {
	$value =~ m/^[0-9]{1,3}$/ && $value >= 8 && $value <= 256 && return 1;
	} elsif ( $ptype eq 'listen' ) {
		if ( $value =~ m/^[0-9a-f:\.]+$/i ) {
			return ip_check_syntax( $value );
		}
		if ( $value =~ m/^([0-9a-f:\.]+)\s+\[([0-9]{1,5})\]$/i ) {
			my $ip = $1;
			my $port = $2;
			return 0 if ! ip_check_syntax ( $ip );
			return 0 if $port !~ m/^[0-9]{1,5}$/;
			return 1;
		}
		return 0;
	} elsif ( $ptype eq 'shell_command' ) {
		if ( $value =~ m/^"?([\S]+)\s+.*"?$/i ) {
			if ( ! -x $1 ) {
				prog_warn 'err', "$property - cannot execute $1";
				return 0;
			}
			return 1;
		}
		return 0;
	} elsif ( $ptype =~ m/^(group|user)$/ ){
		if ( $value !~ m/^[-_0-9a-zA-Z]+$/i ) {
			return 1;
		}
		if ( $ptype eq 'group' && getgrnam($value) ne '' ) {
			return 1;
		}
		if ( $ptype eq 'user' && getpwnam($value) ne '' ) {
			return 1;
		}
		return 0;
	} elsif ( $ptype eq 'path_conf_file' ) {
		if ( $value =~ m/^\"?([^\"\s]+)\"?$/i ) {
			if ( ! -r $1 ) {
				prog_warn 0, "$property - cannot read file $1";
				return 0;
			}
			return 1;
		}
		return 0;
	} elsif ( $ptype =~ m/^(path_generated_file|path_chroot_dir)$/ ) {
		if ( $value =~ m/^\"?([^\"\s]+)\"?$/i ) {
			my $dir = dirname($1);
			if ( ! defined $dir || $dir eq '' ) {
				prog_warn 0, "$property - directory does not exist"; 
				return 0;
			}	
			if ( ! -r $dir ) {
				prog_warn 0, "$property - cannot access directory $dir";
				return 0;
			}
			return 1;
		}
		return 0;
	} elsif ( $ptype eq 'path_certificate' ) {
		if ( $value =~ m/^\"?([^\"\s]+)\"?$/i ) {
			if ( ! -r $1 ) {
				prog_warn 0, "$property - cannot read directory $1";
				return 0;
			}
			return 1;
		}
		return 0;
	} elsif ( $ptype eq 'peers_certfile' ){
		# TODO - do we need do something extra for plain_rsa?
		$value =~ m/^(dnssec|plain_rsa)$/i && return 1;
		if ( $value =~ m/^x509\s+\"?([^\"\s]+)\"?\s*$/i ) {
			if (-r "$global{'path_certificate'}/$1") {
				return 1;
			} else {
				prog_warn 0, "$property - cannot read $global{'path_certificate'}/$1";
				return 0;
			}
		}
		return 0;
	} elsif ( $ptype eq 'certificate' ) {
		if ( $value =~ m/^x509\s+\"?([^\"\s]+)\"?\s+\"?([^\"\s]+)\"?\s*$/i ) {
			if ( ! -r "$global{'path_certificate'}/$1" ) {
				prog_warn 0, "$property - cannot read $global{'path_certificate'}/$1";
				return 0;
			}
			if ( ! -r "$global{'path_certificate'}/$2" ) {
				prog_warn 0, "$property - cannot read $global{'path_certificate'}/$2";
				return 0;
			}
			return 1;
		}
		return 0;
	} elsif ( $ptype eq 'identifier' ) {
		if ( $value =~ m/^address\s*$/i ) {
			return 1;
		}
		if ( $value =~ m/^address\s+([0-9a-f:\.]+)\s*$/i ) {
			local $ip = $1;
			return ip_check_syntax($ip);
		}
		if ( $value =~ m/^fqdn\s+"?([-a-z0-9\._]+)"?\s*$/i ) {
			return 1;
		}
		if ( $value =~ m/^user_fqdn\s+"?([-a-z0-9\.\@_]+)"?\s*$/i ) {
			return 1;
		}
		if ( $value =~ m/^asn1dn\s+"?([-a-z0-9\.\@_\s\\\/='\[\]]+)"?\s*$/i ) {
			return 1;
		}
		if ( $value =~ m/^asn1dn\s*$/i ) {
			return 1;
		}
		if ( $value =~ m/^keyid\s+\"?(\/[^\"\s]+)\"?$/i ) {
			if ( -r $1 ) {
				return 1;
			} else {
				prog_warn 0, "$property - cannot read $1";
				return 0;
			}
		}
		return 0;
	} elsif ( $ptype eq 'upperspec' ) {
		if ( ($protoname, $protoaliases, $protonumber ) 
			= getprotobyname $value ) {
			return 1;
		}
		$value =~ m/^(any|icmp6)$/i && return 1;
		if ( $value =~ m/^icmp6[ \t]+([0-9]{1,3})$/i ) {
			return 1 if ( $1 >= 0 && $1 <= 255 );
		}
		if ( $value =~ m/^icmp6[ \t]+([0-9]{1,3}),([0-9]{1,3})$/i ) {
			return 1 if ( $1 >= 0 && $1 <= 255 && $2 >= 0 && $2 <= 255 );
		}
		if ( $value =~ m/[0-9]{1,5}/ && $value > 0 && $value <= 65535 ) {
			return 1;
		}
		return 0
	} elsif ( $ptype eq 'ip' ) {
		return ip_check_syntax($value);
	} elsif ( $ptype eq 'port' ) {
		my $port;
		if (  $port = getservbyname ($value, '' )) {
			return 1;
		}
		if ($value =~ m/^\[?(any|[0-9]{1,5})\]?$/i ) {
			$port = $1;
		} else {
			return 0;
		}
		if ( $port ne 'any' ) {
			return 0 if ( $port < 0 || $port > 65535 );
		}
		return 1;
	} elsif ( $ptype eq 'range' ) {
		my $valid = 1;
		my ($ip, $mask, $port, $type);
		
		# make sure we have only 1 slash;
		return 0 if $value =~ m/^.*\/.*\/.*$/;

		# Split range into address, mask and port
		if ( $value !~ m/^.*\[(any|[0-9]{1,5})\]$/i ) {
			$value .= "[any]";
		}
               if ( $value =~ m/^(.*)\/([0-9]{1,5})\[(any|[0-9]{1,5})\]$/i ) {
			$ip = $1;
			$mask = $2;
			$port = $3;
               } elsif ( $value =~ m/^(.*)\[(any|[0-9]{1,5})\]$/i ) {
			$ip = $1;
			$mask = 255;
			$port = $2;
		} elsif ( $value =~ m/^(.*)$/i ) {
			$ip = $1;
			$mask = 255;
			$port = 'any';
		} else { 
			return 0;
		}
		
		# Work out type of IP address
		if ( $ip =~ m/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/ ) {
			$type = 'ipv4';
		} elsif ( $ip =~ m/^::$|^[0-9a-f]{1,4}:[0-9a-f:]*:[0-9a-f]{0,4}$/i ) {
			$type = 'ipv6';
		} else {
			return 0;
		}

		# Check IP address
		if ( ! ip_check_syntax($ip) && $ip ne '::' ) {
			$valid = 0;
		}

		# Check mask
		if ( $mask != 255 ) {
			if ( $type eq 'ipv4') {
				$valid = 0 if ( $mask < 0 || $mask > 32 );
			} else {
				$valid = 0 if ( $mask < 0 || $mask > 128 );
			}
		}

		# Check port
		if ( $port ne 'any' ) {
			$valid = 0 if ( $port < 0 || $port > 65535 );
		}

		return $valid;
	}
	else {
		return 0;
	}
	return 0;
}

# Check for required parameters for activation
sub conn_check_required () {
	foreach my $connection ( keys %connection_list ) {
		my $makelive = 1;
		my $chndl = $connection_list{$connection};
		next if $connection eq '%default';
		if ( $connection ne '%anonymous' ) {
			foreach my $property ( @conn_required_props ) {
				$makelive = 0 if ! defined $chndl->{$property};
			}
			# Check that address families of src_range and dst_range match 
			my $src_range_iptype = $chndl->{'src_range_iptype'};
			my $dst_range_iptype = $chndl->{'dst_range_iptype'};
			if ($src_range_iptype ne $dst_range_iptype) {
				prog_warn 0, "$connection - src_range '${src_range_iptype}' does not match dst_range '${dst_range_iptype}'.";
				$makelive = 0;
			}
			# Check that address families of dst_ip and src_ip match
			my $src_ip_iptype = $chndl->{'src_ip_iptype'};
			my $dst_ip_iptype = $chndl->{'dst_ip_iptype'};
			if ($src_ip_iptype ne $dst_ip_iptype) {
				prog_warn 0, "$connection - src_ip '${src_ip_iptype}' does not match dst_ip '${dst_ip_iptype}'.";
				$makelive = 0;
			}
			# check peer
			my $dst_ip = $chndl->{'dst_ip'};
			if ( ! defined $dst_ip
				|| ! defined $peer_list{$dst_ip}  
				|| ! defined $peer_list{$dst_ip}{'makelive'}
				|| $peer_list{$dst_ip}{'makelive'} == 0  ) { 
				$makelive = 0;
			}
		}
		
		$makelive = 0 if ( $chndl->{'syntax_error'} );
		if (! $makelive) {
			prog_warn 0, "$connection - required parameters missing, peer missing or syntax error.";
			prog_warn 0, "$connection - not activating.";
			$chndl->{'makelive'} = 0;
			next;
		}
		$chndl->{'makelive'} = 1;
	}
}

# Translate /etc/services name to port
sub getportnum($) {
	my $port = shift;
	my $value;

	if ($port =~ m/^(any|\[any\])$/ ) {
		return $port;
	}
	if ($value = getservbyname( $port, '')){
		return $value;
	}
	return $port;
}

# Fill in default missing parameters
sub conn_fillin_defaults () {
	foreach my $connection ( keys %connection_list ) {
		next if $connection eq '%default';
		my $chndl = $connection_list{$connection};
		foreach my $property ( keys %{ $connection_list{'%default'} } ) {
			if ( ! defined $chndl->{$property} ) {
				$chndl->{$property} = $connection_list{'%default'}{$property};
			}
		}
		next if ! defined $chndl->{'src_ip'};
		next if ! defined $chndl->{'dst_ip'};

		# Set up default values for range and ID if they do not exist already
		foreach my $p ( 'src', 'dst' ) {
			if ( ! defined $chndl->{"${p}_range"} ) {
				$chndl->{"${p}_range"}
					= $chndl->{"${p}_ip"};
			}
			if ( $chndl->{"${p}_range"} 
				!~ m/^.*\[(any|[0-9]{1,5})\]$/ ) {
				$chndl->{"${p}_range"} .= "[any]";
			}
			# Remove full length netmasks to avoid confusing things...
			if ($chndl->{"${p}_range"} =~ m/^[0-9]{1,3}\./) {
				$chndl->{"${p}_range"} =~ s/\/32//;
				$chndl->{"${p}_range_iptype"} = 'ip4';
			} elsif ($chndl->{"${p}_range"} =~ m/^([0-9a-f]{1,4}:|::)/) {
				$chndl->{"${p}_range"} =~ s/\/128//;
				$chndl->{"${p}_range_iptype"} = 'ip6';
			}
			# Record IP types if dst_ip and src_ip
			if ($chndl->{"${p}_ip"} =~ m/^[0-9]{1,3}\./) {
				$chndl->{"${p}_ip_iptype"} = 'ip4';
			} elsif ($chndl->{"${p}_ip"} =~ m/^([0-9a-f]{1,4}:|::)/) {
				$chndl->{"${p}_ip_iptype"} = 'ip6';
			}
		}

		# Work out IDs for use with racoon configuration
		# Remove any port information as racoon sees it as duplicate sainfo...
		my $local_id = $chndl->{'src_range'};
		$local_id =~ m/^(\S+)(\[(any|[0-9]{1,5}|[-0-9a-z]+)\])$/;
		my $src_port = $2;
		$local_id = $1;
		$chndl->{'local_id'} = $local_id;
		$chndl->{'src_subnet'} = $local_id;
		$chndl->{'src_port'} = getportnum($src_port);
		my $remote_id = $chndl->{'dst_range'};
		$remote_id =~ m/^(\S+)(\[(any|[0-9]{1,5}|[-0-9a-z]+)\])$/;
		my $dst_port = $2;
		$remote_id = $1;
		$chndl->{'remote_id'} = $remote_id; 
		$chndl->{'dst_subnet'} = $remote_id; 
		$chndl->{'dst_port'} = getportnum($dst_port); 
		
		# Set the mode appropriately if not already set
		if ( !defined $chndl->{'mode'} ) {
			if ( $chndl->{'src_range'}
					eq $chndl->{'src_ip'} . "[any]"
				&& $chndl->{'dst_range'}
					eq $chndl->{'dst_ip'} . "[any]" ) {
				$chndl->{'mode'} = 'transport';
			} else {
				$chndl->{'mode'} = 'tunnel';
			}
		}

		# Deal with SPD port rules
		my $pindexes = $chndl->{'pindexes'} ;
		# Work out if this is a multi SPD connection
		if ( ! scalar(@$pindexes)) {
			$chndl->{'multi_spd'} = 0;
			next;
		}
		$chndl->{'multi_spd'} = 1;
		foreach my $ind ( @$pindexes ) {
			# fill in missing ports, and add missing '[]'s
			foreach my $p ( 'src', 'dst' ) {
				my $pname = "${p}_port" . "[${ind}]";
				$chndl->{$pname} = '[any]' if ( ! defined $chndl->{$pname} );
				$chndl->{$pname} = getportnum($chndl->{$pname});
				$chndl->{$pname} =~ s/^(any|[0-9]{1,5})$/[${1}]/;
				$chndl->{"${p}_range[${ind}]"} = $chndl->{"${p}_subnet"} . $chndl->{"${p}_port[${ind}]"};
			}
			foreach my $p ( 'level', 'encap', 'policy' ) {
				my $pname = "${p}" . "[${ind}]";
				$chndl->{$pname} = $chndl->{$p} if ( ! defined $chndl->{$pname} );
			}
		}
	} 
}

sub prop_get_indexes (\%) {
	my $hndl = shift;
	my %tmp;

	my @keys = keys %$hndl;
	@keys = grep /^.*\[[-_0-9a-z]+\]$/, @keys;
	map { s/^.*\[([-_0-9a-z]+)\]$/$1/; } @keys;
	$tmp{$_} = 1 foreach (@keys);
	@keys = reverse (sort (keys (%tmp)));
	
	return @keys;
}

sub prop_store_index (\%$) {
	my $hndl = shift;
	my $property = shift;
	
	if ( ! defined $hndl->{'pindexes'} ) {
		$hndl->{'pindexes'} = [];
	}
	if ($property =~ m/^\S+\[([-_0-9a-z]+)\]$/) {
		$pindex = $1;
		return if ( grep { $_ eq $pindex} @{ $hndl->{'pindexes'}});  
		push @{ $hndl->{'pindexes'} }, $pindex;
	}
}

sub peer_fillin_defaults () {

	# Copy default to defined peers
	my $dhndl = $peer_list{'%default'};
	foreach my $peer ( keys %peer_list ) {
		next if $peer eq '%default';
		my $phndl = $peer_list{$peer};

		foreach my $property ( keys %{ $dhndl } ) {
			if ( ! defined $phndl->{$property} ) {
				$phndl->{$property} = $dhndl->{$property};
			}
			prop_store_index(%{ $phndl }, $property)
		}
	}
			
	foreach my $peer ( keys %peer_list ) {
		my $phndl = $peer_list{$peer};
		# Fill in all proposals...
		my $pindexes = $phndl->{'pindexes'};
		foreach my $property ( grep { $_ = $1 if /^(.*)\[[-_0-9a-z]+\]$/;  } keys %$dhndl ) {
			foreach my $ind ( @$pindexes ) {
				next if $peer eq '%default' && $ind == 0;
				my $name =  "$property" . '[' . "$ind" . "]";
				my $dname = "$property" . '[0]';
				if ( ! defined $phndl->{"$name"} ) {
					$phndl->{"$name"} = $dhndl->{"$dname"}
				}
			}
		}

	}

	# If a peer does not exist, create it from %default
	my @peers = keys %peer_list;
	foreach my $connection ( keys %connection_list ) {
		next if $connection eq '%default';
		my $conn_hndl = $connection_list{$connection};
		next if ! defined $conn_hndl->{'dst_ip'};
		my $ip_addr = $conn_hndl->{'dst_ip'};
		next if grep { $ip_addr eq $_ } @peers;
		
		foreach my $element ( keys %{ $peer_list{'%default'} } ) {
			$peer_list{$ip_addr}{$element} = $peer_list{'%default'}{$element};
		}
	}

	# fill in dst_ip property if not already done...
	foreach my $peer ( keys %peer_list ) {
		next if $peer eq '%default';
		$peer_list{$peer}{'dst_ip'} = $peer;
	}

	# Fix up missing " ...
	foreach my $peer ( keys %peer_list ) {
		my $phndl = $peer_list{$peer};
		foreach my $prop ( 'my_identifier', 'peers_identifier', 'certificate_type', 'peers_certfile') {
			my $ptype = get_proptype('peer', "$prop");
			next if ! defined $phndl->{"$prop"};
			my $value = $phndl->{"$prop"};
			if ( $ptype eq 'peers_certfile' ){
				next if $value =~ m/^dnssec$/i;
				if ( $value =~ m/^(x509|plain_rsa)\s+\"?(\S+)\"?\s*$/i ) {
					$phndl->{"$prop"} = "$1" . ' "' . "$2" . '"';
				}
			} elsif ( $ptype eq 'certificate' ) {
				if ( $value =~ m/^x509\s+\"?(\S+)\"?\s+\"?(\S+)\"?\s*$/ ) {
					$phndl->{"$prop"} = "x509 " . '"' . $1 . '" "' . $2  . '"'; 
				}
			} elsif ( $ptype eq 'identifier' ) {
				next if $value =~ m/^address\s*$/i; 
				next if $value =~ m/^asn1dn\s*$/i;
				if ( $value =~ m/^address\s+([0-9a-f:\.]+)\s*$/i ) {
					$phndl->{"$prop"} = "address $1";
				}
				if ( $value =~ m/^fqdn\s+"?([-a-z0-9\._]+)"?\s*$/i ) {
					$phndl->{"$prop"} = "fqdn " . '"' . $1 . '"'; 
				}
				if ( $value =~ m/^user_fqdn\s+"?([-a-z0-9\.\@_]+)"?\s*$/i ) {
					$phndl->{"$prop"} = "user_fqdn " . '"' . $1 . '"'; 
				}
				if ( $value =~ m/^asn1dn\s+"?([-a-z0-9\.\@_\s\\\/='\[\]]+)"?\s*$/i ) {
					$phndl->{"$prop"} = "asn1dn " . '"' . $1 . '"'; 
				}
				if ( $value =~ m/^keyid\s+"?(\/\S+)"?$/i ) {
					$phndl->{"$prop"} = "keyid " . '"' . $1 . '"'; 
				}
			}
		}
	}
	
}

sub peer_check_required () {

	# For now, every peer has required values...
PEER:	foreach my $peer ( keys %peer_list ) {
		my $makelive = 1;
		next PEER if $peer eq '%default';
	
                $makelive = 0 if ( $peer_list{$peer}{'syntax_error'} );
                if (! $makelive) {
                        prog_warn 0, "$peer - required parameters missing or syntax error.";
                        prog_warn 0, "$peer - not activating.";
                        $peer_list{$peer}{'makelive'} = 0;
                        next PEER;
                }
                
		$peer_list{$peer}{'makelive'} = 1;
	}
}



# print connection output
sub global_dump_list () {
	print "global: ";
	foreach my $prop ( keys %global ) {
		print "$prop=$global{$prop} ";
	}
	print "\n";
}

sub peer_dump_list () {
	foreach my $peer ( keys %peer_list ) {
		print "$peer: ";
		foreach my $property ( keys %{ $peer_list{$peer} } ) {
			print "$property=$peer_list{$peer}{$property} ";
		}
		print "\n";
	}
}

sub conn_dump_list () {
	foreach my $connection ( keys %connection_list ) {
		print "$connection: ";
		foreach my $property ( keys %{ $connection_list{$connection} } ) {
			print "$property=$connection_list{$connection}{$property} ";
		}
		print "\n";
	}
}

# setup the kernel
sub setkey_start () {
	# Flush and reinit kernel 
	sadspd_reset();

	# Load all peers
}

sub setkey_stop () {
	# Flush kernel
	spd_flush();
	sad_flush();
}

# Reset SAD and SPD
sub spd_reset () {
	spd_flush ();
	spd_init ();
}

sub sad_reset () {
	sad_flush ();
	sad_init ();
}

# Fill in spdadd command
sub spd_fill_add ($) {
	my $connection = shift;
	my $stuff;

	my $hndl = $connection_list{$connection};
	$stuff = $spdadd{$$hndl{'spdadd_template'}};

	# We only do interesting things on %default templates	
	if ($hndl->{'spdadd_template'} eq '%default') {
		my $pindexes = $hndl->{'pindexes'};
		my $multi_spd = scalar( @$pindexes );
		if ($multi_spd > 0) {
			if ($hndl->{'src_range_iptype'} eq 'ip4') {
				$stuff = $spdadd_ip4_header;
			} elsif ($hndl->{'src_range_iptype'} eq 'ip6') {
				$stuff = $spdadd_ip6_header;
			}
			# Build multi SPD template
			foreach my $ind ( @$pindexes ) {
				my $to_add;
				my $pname = "policy[${ind}]";
				if ($hndl->{$pname} eq 'ipsec') {
					$to_add = $spdadd_default;
				} else {
					$to_add = $spdadd_alternate_policy;
				}
				$to_add =~ s/___(encap|level|policy|src_range|dst_range)___/___$1\[$ind\]___/gm;
				$stuff .= $to_add;
			}

		} else {
			# Original non-multi SPD template action
			# Use transport template if needed
			if ($hndl->{'mode'} eq 'transport'
				&& $hndl->{'upperspec'} eq 'any'
				&& $hndl->{'src_range'} =~ m/^.*\[any\]$/
				&& $hndl->{'dst_range'} =~ m/^.*\[any\]$/) {
				if ($hndl->{'src_range_iptype'} eq 'ip4') {
					$stuff = $spdadd{'%transport_ip4_default'};
				} elsif ($hndl->{'src_range_iptype'} eq 'ip6') {
					$stuff = $spdadd{'%transport_ip6_default'};
				}
			}
		}

		#
		# Do fill in AH header if asked for.
		if ($hndl->{'encap'} eq 'esp' 
			&& ($hndl->{'mode'} eq 'transport' 
				&& $bool_val{"$hndl->{'auto_ah_on_esp'}"} != 0
				|| $bool_val{"$hndl->{'always_ah_on_esp'}"} != 0)) {
			$stuff =~ s/^(\s*spdadd.*out ipsec\s*\n.*);$/${1}\n${spdadd_addons{'ah_out'}};/mg;
			$stuff =~ s/^(\s*spdadd.*in ipsec\s*\n.*);$/${1}\n${spdadd_addons{'ah_in'}};/mg;
		}
		#  
		# Do fill in values for compression
		if (defined $hndl->{'compression'} 
			&& $bool_val{"$hndl->{'compression'}"} != 0) {
			$stuff =~ s/^(\s*spdadd.*out ipsec\s*)$/${1}\n${spdadd_addons{'ipcomp_out'}}/mg;
			$stuff =~ s/^(\s*spdadd.*in ipsec\s*)$/${1}\n${spdadd_addons{'ipcomp_in'}}/mg;
		}

	}	

	foreach my $key (keys %$hndl) {
		my $key_reg = $key;
		$key_reg =~ s/\[/\\[/g;
		$key_reg =~ s/\]/\\]/g;
		$stuff =~ s/___${key_reg}___/$$hndl{"$key"}/img;
	}

	#
	# spd priority only supported on Linux kernels
	if (($^O !~ /linux/i) && ($hndl->{'spdadd_template'} eq '%default') ) {
		$stuff =~ s/^(\s*spdadd.*(in|out))\s+prio.*(ipsec|discard;|none;)$/${1} ${3}/mg;
	}	
			

	return $stuff;
}

# Load the SPD
sub spd_load (;$) {
	my $conn = shift;
	my $setkey_buffer = '';
	my @conns = ();
	my @spd_list;
	my %conn_spd_hash;

	parse_spd(@spd_list, %conn_spd_hash);
	if ( defined $conn ) {
		return 0 if ( ! grep /^${conn}$/, (keys %connection_list) );
		return -1 if ( ! $connection_list{$conn}{'makelive'} );
		return -2 if ( grep /^${conn}$/, keys %conn_spd_hash );
		@conns = ( $conn );
	} else {
		@conns = keys %connection_list;
	}

	open ( SETKEY, '|-' )
		|| exec ("$setkey_cmd -f /dev/stdin 2>&1 | $0 -l" );
	for my $connection ( @conns ) {
		next if $connection eq '%default';
		next if $connection eq '%anonymous';
		next if grep /^${connection}$/, keys %conn_spd_hash;
		my $hndl = $connection_list{$connection};
		next if ! $$hndl{'makelive'};
		next if ! $bool_val{$$hndl{'admin_status'}};
		my $stuff = spd_fill_add ($connection);
		$setkey_buffer .= $stuff. "\n";
		print SETKEY <<"EOF";
$stuff
EOF
	}
	close SETKEY;
	my $err = $?;
	if ( $err ) {
		my $i = 1;
		foreach my $line ( split /^/m, $setkey_buffer ) {
			chomp $line;
			prog_warn 0, "setkey input: $i $line";
			$i++;
		}
		prog_die "loading SPD failed - exit code " . ($err >> 8);
	}
	sleep($quiesce) if ($quiesce > 0);
	return 1;
}

# Initialise the SPD
sub spd_init() {
	open ( SETKEY, '|-' )
		|| exec ($setkey_cmd, '-f', '/dev/stdin');
	$spdinit = '' if ! defined $spdinit;
	print SETKEY <<"EOF";
spdflush;
$spdinit
EOF

	close SETKEY or prog_die "initialising SPD failed - exit code " . ($? >> 8);
	sleep($quiesce) if ($quiesce > 0);
	return 1;
}

# Initialise the SAD
sub sad_init() {
	open ( SETKEY, '|-' )
		|| exec ($setkey_cmd, '-f', '/dev/stdin');
	$sadinit = '' if ! defined $sadinit;
	print SETKEY <<"EOF";
$sadinit
EOF

	close SETKEY or prog_die "initialising SPD failed - exit code " . ($? >> 8);
	sleep($quiesce) if ($quiesce > 0);
	return 1;
}


# Flush the SAD
sub sad_flush () {
	setkey_flush('SAD');
}

# Flush the SPD
sub spd_flush() {
	setkey_flush('SPD');
}

sub setkey_flush ($) {
	my $table = shift;
	my $cleanret = 0;
	my $arg = "";

	if ( $table =~ /SAD/ ) {
		$arg = "";
	}
	elsif ( $table =~ /SPD/ ) {
		$arg = "-P";
	} else {
		prog_die "setkey_flush() - wrong arg $table";
	} 

	open ( SETKEY, '-|' )
		|| exec ("$setkey_cmd $arg -F 2>&1");
	while ( <SETKEY> ) {
		if ( m/pfkey_open: Address family not supported by protocol/ ) {
			$cleanret = 1;
			next;
		}
		chomp;
		prog_warn 0, "setkey said: $_";
		# print "$_\n";
	}
	
	close SETKEY;
	prog_die ("flushing $table failed - exit code " . ($? >> 8)) 
			if ( $? && ! $cleanret);
	sleep($quiesce) if ($quiesce > 0);
	return 0
}

sub spd_show () {
	setkey_show('SPD');
}

sub sad_show () {
	setkey_show('SAD');
}

sub setkey_show ($) {
	my $table = shift;
	my $cleanret = 0;
	my $arg = "";

	if ( $table =~ /SAD/ ) {
		$arg = "";
	}
	elsif ( $table =~ /SPD/ ) {
		$arg = "-P";
	} else {
		prog_die "setkey_show() - wrong arg $table";
	} 

	system ("$setkey_cmd $arg -D | $pager_cmd @pager_flags");

	return 0
}

sub mod_start () {

	# Only do this if on linux
	return 0 if ($^O !~ /linux/i);

	print "Loading IPSEC/crypto modules...\n";

	# Load cryptographic modules
	mod_start_crypto ();

	# Load xfrm and af_key
	mod_load "$modpath_xfrm/xfrm_user${modext}";
	mod_load "$modpath_key/af_key${modext}";

	# Load IPv4 IPSEC
	mod_start_ipsec ();
	
	# Load IPv6 IPSEC
	mod_start_ipsec6 ();

	print "IPSEC/crypto modules loaded.\n";	
	prog_warn 'info', "loaded IPSEC/crypto modules.";	

	return 0;
}

sub mod_stop () {
	
	# Only do this if on linux
	return 0 if ($^O !~ /linux/i);

	print "Unloading IPSEC/crypto modules...\n";

	# Unload crypto modules
	mod_stop_crypto ();

	# Unload xfrm and af_key
	mod_unload "$modpath_xfrm/xfrm_user${modext}";
	mod_unload "$modpath_key/af_key${modext}";

	# Unload IPv4 IPSEC
	mod_stop_ipsec ();

	# Unload IPv6 IPSEC
	mod_stop_ipsec6 ();

	print "IPSEC/crypto modules unloaded.\n";
	prog_warn 'info', "unloaded IPSEC/crypto modules";

	return 0;
}

sub mod_start_ipsec6 () {

	return 0 if ! -d $proc_ipv6;

	for my $mod ( @modules_ipsec6 ) {
		mod_load "${modpath_ipsec6}/${mod}${modext}";
	}

	return 0;
}

sub mod_stop_ipsec6 () {

	for my $mod ( @modules_ipsec6 ) {
		mod_unload $mod;
	}
	
	return 0;
}


sub mod_start_ipsec () {

	return 0 if ! -d $proc_ipv4;

	for my $mod ( @modules_ipsec ) {
		mod_load "${modpath_ipsec}/${mod}${modext}";
	}

	return 0;
}

sub mod_stop_ipsec () {

	for my $mod ( @modules_ipsec ) {
		mod_unload $mod;
	}
	
	return 0;
}

sub mod_start_crypto () {
	local @modfiles;
	
	return 0 if ( ! -d  $modpath_crypto );

	# Load zlib_deflate if present
	mod_load "$modpath_zlib/zlib_deflate${modext}";

	opendir DIR, $modpath_crypto or prog_die "$modpath_crypto - $!";
	@modfiles = grep /${modext}$/, readdir DIR;
	closedir DIR;

	for my $mod ( @modfiles ) {
		next if ( $mod =~ /tcrypt${modext}$/ );
		mod_load "$modpath_crypto/$mod";
	}

	return 0
}

sub mod_stop_crypto () {
	local @modfiles;
	
	return 0 if ( ! -d  $modpath_crypto );

	opendir DIR, $modpath_crypto or prog_die "$modpath_crypto - $!";
	@modfiles = grep /${modext}$/, readdir DIR;
	closedir DIR;
	for my $mod ( @modfiles ) {
		mod_unload $mod;
	}

	# Unload zlib_deflate if present
	mod_unload "$modpath_zlib/zlib_deflate${modext}";

	return 0
}

sub mod_load ($) {
	local $modtoload = shift;
	local $modname;

	# Check that kernel supports modules
	return 1 if ( ! -f $proc_modules );

	return 1 if ( ! -f $modtoload );

	return 1 if ( ! -f "/sbin/modprobe" );

	$modname = basename("$modtoload", "$modext");

	if ( ! grep /^${modname}$/, @modules ) {
		system ( "/sbin/modprobe $modname" );
	}

	return 0

}

sub mod_unload ($) {
	my $modname = shift;

	$modname =  basename("$modname", "$modext");

	if ( ! grep /^${modname}$/, @modules ) {
		return 0;
	}

	system ( "/sbin/modprobe -r $modname > /dev/null 2>&1" );
	
	return 0;
}

sub mod_ls () {
	local $module;
	
	# Only do this if on linux
	return 0 if ($^O !~ /linux/i);

	if (@modules > 0) {
		return 0
	}
	
	# Check that kernel supports modules
	if ( ! -f $proc_modules ) {
		return 1;
	}

	open MOD, "<$proc_modules";
	while ($module = <MOD>) {
		chomp $module;
		next if ($module =~ /^Module\s+Size/);
		$module =~ s/^([a-zA-Z0-9_\-]+)\s+.*$/$1/;
		push @modules, $module;
	}
	close MOD;

	return 0;
}



