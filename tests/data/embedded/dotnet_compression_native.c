/*
 * Mirrors libSystem.IO.Compression.Native from the .NET 8 runtime pack: its
 * own export family (CompressionNative_*) and the native build stamp
 * (dotnet/runtime eng/native/version/_version.c), which sits in .data.
 * Built together with brotli_error_table.c -DBARE_NAMES, the 1.0.x brotli
 * copy .NET 8 bundles. -DPRODUCT_VERSION adds the product version string
 * libcoreclr carries.
 */
__attribute__((used)) static char sccsid[] =
    "@(#)Version 8.0.3226.50405 @Commit: b9a49e4a6d3a444a3685e318c74a7892d01873f7";

#ifdef PRODUCT_VERSION
__attribute__((used)) const char *const product_version = PRODUCT_VERSION;
#endif

unsigned int CompressionNative_Crc32(unsigned int crc, const unsigned char *buf, int len) {
  (void)buf;
  return crc + (unsigned int)len + (unsigned int)sccsid[0];
}
