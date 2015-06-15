#!/bin/sh
# Generate tokens for torrc fuzzing

TOR="src/or/tor"

# @1 - socks port options, log domains

ECHO_N="/bin/echo -n"
ECHO="/bin/echo"

#echo "Generating tokens:"

# Create a token from each torrc option
for opt in `"$TOR" --list-torrc-options`; do
  $ECHO "option_$opt = \"$opt\""
done;

# Create tokens from torrc bandwidth and RAM option parameters
for opt in bytes KBytes MBytes GBytes KBits MBits GBits KB MB GB; do
  $ECHO "parameter_size_$opt = \"$opt\""
done;

# Create tokens from torrc plugin & port option parameters
# skip single-byte: \: \= \. \: \/ \* \,
for opt in socks4 socks5 exec auto; do
  $ECHO "parameter_port_$opt = \"$opt\""
done;

# Create tokens from torrc socks port option parameters
for opt in IsolateClientAddr No IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr SessionGroup NoIPv4Traffic IPv6Traffic PreferIPv6 CacheIPv4DNS CacheIPv6DNS CacheDNS UseIPv4Cache UseIPv6Cache UseDNSCache PreferIPv6Automap PreferSOCKSNoAuth; do
  $ECHO "parameter_socks_$opt@1 = \"$opt\""
done;

# Create tokens from torrc ORPort option parameters
for opt in NoAdvertise NoListen IPv4Only IPv6Only; do
  $ECHO "parameter_orport_$opt = \"$opt\""
done;

# Create tokens from torrc descriptor option parameters
for opt in v3 bridge; do
# skip single-byte: \,
  $ECHO "parameter_descriptor_$opt = \"$opt\""
done;

# Create tokens from torrc dir option parameters
for opt in orport id weight bridge v3ident; do
  $ECHO "parameter_dir_$opt = \"$opt\""
done;

# Create tokens from torrc path option parameters
# skip single-byte:
#for opt in \. \/ \~ \: \;; do
#  $ECHO "parameter_path_$opt = \"$opt\""
#done;

# Create tokens from torrc log option parameters
# skip single-byte: \- \~ \* \[ \]
for opt in debug info notice warn err stderr stdout syslog relay; do
  $ECHO "parameter_log_$opt = \"$opt\""
done;

# Create tokens from torrc log domains
for opt in general crypto net config fs protocol mm http app control circ rend bug dir dirserv or edge acct hist handshake; do
  $ECHO "parameter_log_domain_$opt@1 = \"$opt\""
done;

# Create tokens from torrc node option parameters
# skip single-byte: \{ \} \*
for opt in entry exit middle introduction rendezvous; do
  $ECHO "parameter_node_$opt = \"$opt\""
done;
$ECHO "parameter_node_qq = \"??\""

# Create tokens from torrc interval option parameters
# skip single-byte: \:
for opt in msec second seconds minutes hours day days week weeks month months; do
  $ECHO "parameter_interval_$opt = \"$opt\""
done;

# Create tokens from torrc TLSECGroup option parameters
for opt in P224 P256; do
  $ECHO "parameter_TLSECGroup_$opt = \"$opt\""
done;

# Create tokens from torrc transproxy option parameters
for opt in default TPROXY ipfw; do
  $ECHO "parameter_transproxy_$opt = \"$opt\""
done;
$ECHO "parameter_transproxy_pf_divert = \"pf-divert\""

# Create tokens from torrc automap option parameters
# skip single-byte: \. \,
$ECHO "parameter_automap_dot_exit = \".exit\""
$ECHO "parameter_automap_dot_onion = \".onion\""
$ECHO "parameter_automap_dot_tor = \".tor\""

# Create tokens from torrc policy option parameters
# skip single-byte: \- \: \/ \. \[ \] \*
for opt in accept reject accept6 reject6; do
  $ECHO "parameter_policy_$opt = \"$opt\""
done;

# Create tokens from torrc numeric option parameters
# skip single-byte:
#for opt in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
#  $ECHO "parameter_numeric_$opt = \"$opt\""
#done;

# Create a space token
# skip single-byte:
#$ECHO "parameter_space = \" \""

# Create newline tokens
# skip single-byte:
#$ECHO "parameter_newline = \"\x0a\""
#$ECHO "parameter_carriage_return = \"\x0d\""
