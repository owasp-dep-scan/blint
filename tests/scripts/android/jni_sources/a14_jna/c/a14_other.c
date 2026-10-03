/* The second exporter: a14_ambiguous (a real two-library ambiguity) and
 * a14_helper_mul (the decoy the register call's constant must refuse). */
int a14_ambiguous(int x) { return x + 3; }
int a14_helper_mul(int a, int b) { return a * b + 1; }
