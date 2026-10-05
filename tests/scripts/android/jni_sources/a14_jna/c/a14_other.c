/* The second exporter: a14_ambiguous, a14_stale and a14_branch (real
 * two-library ambiguities, no constant naming the library) and
 * a14_helper_mul (the decoy the register call's constant must refuse). */
int a14_ambiguous(int x) { return x + 3; }
int a14_helper_mul(int a, int b) { return a * b + 1; }
int a14_stale(int x) { return x + 11; }
int a14_branch(int x) { return x + 12; }
