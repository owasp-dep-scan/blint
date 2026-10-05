/*
 * The JNA dispatch library stand-in. The join's jna_direct path requires
 * the app to ship libjnidispatch.so for an ABI before any binding is
 * made there; this empty library carries the name (JNA's real dispatch
 * library is LGPL and is never committed - the join's requirement is
 * name presence, which is all a static join can read).
 */
