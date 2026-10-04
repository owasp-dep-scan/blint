/*
 * A14 W1 fixtures - the JNA direct-mapping library side.
 *
 * Every function is a plain exported C symbol: JNA's Native.register
 * binds a class's static native methods to the exported symbols of the
 * same name in the registered library, so these names are the whole
 * contract. liba14other (a14_other.c) exports the decoy names: an
 * ambiguous exporter side where no constant names the library, and a
 * constant-decided one where it does.
 */
int a14_direct_add(int a, int b) { return a + b; }
int a14_helper_mul(int a, int b) { return a * b; }
int a14_via_init(int x) { return x + 1; }
int a14_twin_echo(int x) { return x; }
int a14_ambiguous(int x) { return x + 2; }
int a14_bootstrap_decoy(int x) { return x + 4; }
int a14_bootstrap_real(int x) { return x + 5; }
int a14_caller_decoy(int x) { return x + 6; }
int a14_self_registrar(int x) { return x + 7; }
int a14_stale(int x) { return x + 8; }
int a14_branch(int x) { return x + 9; }
int a14_outer_fn(int x) { return x + 10; }
