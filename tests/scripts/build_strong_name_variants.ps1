# Builds the strong-name variant fixtures committed under
# tests/data/pe/dotnet-strongname/ (W3.4, ground rule 29 provenance).
#
# Run on the Windows 11 ARM64 VM (any .NET SDK >= 10 works) from any
# directory; artifacts land in C:\Users\appthreat\w34 and are copied into
# the repository by the packet. The key pair is generated fresh each run
# (RSACryptoServiceProvider 1024-bit, CAPI blob = the SNK format), so a
# rebuild produces different tokens than the ones pinned in
# tests/test_pe_dotnet.py — regenerate the records with
# tests/data/pe/dotnet-gt/gtdotnet.cs over the new files if you rebuild.
#
# Variants (facts measured in the packet commit):
#   unsigned.dll      no key, no signature directory
#   signed.dll        /keyfile - full signature, STRONGNAMESIGNED set
#   delaysigned.dll   /delaysign+ - key embedded, null signature, flag clear
#   publicsigned.dll  /publicsign - key embedded, null signature, flag set
#   ivt-signed.dll    signed + two keyed InternalsVisibleTo friends
#   ivt-delay.dll     delay-signed + the same friends
#   ivt-plain.dll     unsigned + one keyless and one keyed friend (a
#                     strong-named parent must key its friends: CS1726)
#
# Measurement note: delayattr.dll from the development script also built
# [assembly: AssemblyDelaySign(true)] explicitly in source with no
# /delaysign switch - the attribute row is NOT emitted and the output is
# fully signed, which is how the packet established that Roslyn consumes
# the pseudo-attribute and delay_sign can only read a row some other
# toolchain (MSVC's managed emitter, the tier-5 MFC pair) wrote.
$ErrorActionPreference = "Stop"
$dir = "C:\Users\appthreat\w34"
New-Item -ItemType Directory -Force -Path "$dir\base","$dir\ivt","$dir\ivtnokey","$dir\dattr" | Out-Null

$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(1024)
[IO.File]::WriteAllBytes("$dir\k.snk", $rsa.ExportCspBlob($true))

$csproj = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <GenerateDocumentationFile>false</GenerateDocumentationFile>
  </PropertyGroup>
</Project>
"@
$lib1 = "namespace W34 { internal class Util { internal static int F(int x) => x + 1; } }"
$lib2 = @"
using System.Reflection;
[assembly: AssemblyDelaySign(true)]
namespace W34 { internal class Util2 { internal static int F(int x) => x + 2; } }
"@
foreach ($p in @("base","ivt","ivtnokey","dattr")) {
  [IO.File]::WriteAllText("$dir\$p\p.csproj", $csproj)
}
[IO.File]::WriteAllText("$dir\base\lib1.cs", $lib1)
[IO.File]::WriteAllText("$dir\dattr\lib2.cs", $lib2)

function Build($proj, $name, $props) {
  $all = @("-c","Release","-p:AssemblyName=$name") + $props
  & dotnet build $proj @all /nologo /v:q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "build failed: $name" }
  Copy-Item "$proj\bin\Release\net10.0\$name.dll" "$dir\$name.dll" -Force
}

Build "$dir\base" "unsigned"  @()
Build "$dir\base" "signed"    @("-p:SignAssembly=true", "-p:AssemblyOriginatorKeyFile=$dir\k.snk")
Build "$dir\base" "delaysigned" @("-p:SignAssembly=true", "-p:DelaySign=true", "-p:AssemblyOriginatorKeyFile=$dir\k.snk")
Build "$dir\base" "publicsigned" @("-p:SignAssembly=true", "-p:PublicSign=true", "-p:AssemblyOriginatorKeyFile=$dir\k.snk")
Build "$dir\dattr" "delayattr" @("-p:SignAssembly=true", "-p:AssemblyOriginatorKeyFile=$dir\k.snk")

$hex = (([Reflection.AssemblyName]::GetAssemblyName("$dir\signed.dll").GetPublicKey()) | ForEach-Object { $_.ToString("x2") }) -join ""
$lib3 = @"
using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("FRIEND.Keyed, PublicKey=$hex")]
[assembly: InternalsVisibleTo("Friend.Second, PublicKey=$hex")]
namespace W34 { internal class Util3 { internal static int F(int x) => x + 3; } }
"@
[IO.File]::WriteAllText("$dir\ivt\lib3.cs", $lib3)
$lib4 = @"
using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("Friend.Plain")]
[assembly: InternalsVisibleTo("FRIEND.Keyed, PublicKey=$hex")]
namespace W34 { internal class Util4 { internal static int F(int x) => x + 4; } }
"@
[IO.File]::WriteAllText("$dir\ivtnokey\lib4.cs", $lib4)
Build "$dir\ivt" "ivt-signed" @("-p:SignAssembly=true", "-p:AssemblyOriginatorKeyFile=$dir\k.snk")
Build "$dir\ivt" "ivt-delay" @("-p:SignAssembly=true", "-p:DelaySign=true", "-p:AssemblyOriginatorKeyFile=$dir\k.snk")
Build "$dir\ivtnokey" "ivt-plain" @()

foreach ($f in @("unsigned","signed","delaysigned","publicsigned","delayattr","ivt-signed","ivt-delay","ivt-plain")) {
  $an = [Reflection.AssemblyName]::GetAssemblyName("$dir\$f.dll")
  $tok = ($an.GetPublicKeyToken() | ForEach-Object { $_.ToString("x2") }) -join ""
  Write-Output ("GetAssemblyName $f.dll => pkt=" + $tok + " pubkey_len=" + $an.GetPublicKey().Length + " flags=" + $an.Flags)
}
