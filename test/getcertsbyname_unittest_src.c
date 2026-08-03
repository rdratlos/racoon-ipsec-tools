/* getcertsbyname.c defines no main() of its own when DNSSEC_DEBUG is not
 * defined (its main()/b64encode() are #ifdef DNSSEC_DEBUG, and this
 * wrapper deliberately does not define it), so this file can include it
 * directly to reach getnewci_unittest() (a new ENABLE_UNITTEST-only
 * accessor for the static getnewci()) alongside freecertinfo()/
 * getcertsbyname() (already exported). */
#include "../src/racoon/getcertsbyname.c"
