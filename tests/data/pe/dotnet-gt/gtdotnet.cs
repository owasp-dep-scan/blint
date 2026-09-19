// Ground-truth dumper for blint W3.1 (ground rule 29): reads managed PE
// metadata with System.Reflection.Metadata plus a spec-based byte-level walk
// of the CLI header, and prints one JSON line per file. Fields mirror blint's
// dotnet block contract (03/A.1): assembly identity, public key token,
// AssemblyRef list, ModuleRefs, P/Invoke surface, entry point, CLI flags,
// target framework.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;

static int RvaToOffset(byte[] pe, int rva)
{
    int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
    int coff = e_lfanew + 4;
    int numSections = BitConverter.ToInt16(pe, coff + 2);
    int opt = coff + 20;
    ushort magic = BitConverter.ToUInt16(pe, opt);
    int ddBase = opt + (magic == 0x20B ? 112 : 96);
    int numDirs = BitConverter.ToInt32(pe, opt + (magic == 0x20B ? 108 : 92));
    if (numDirs <= 14) return -1;
    int secTable = ddBase + numDirs * 8;
    for (int i = 0; i < numSections; i++)
    {
        int s = secTable + i * 40;
        int va = BitConverter.ToInt32(pe, s + 12);
        int rawSize = BitConverter.ToInt32(pe, s + 16);
        int rawPtr = BitConverter.ToInt32(pe, s + 20);
        if (rva >= va && rva < va + rawSize) return rawPtr + (rva - va);
    }
    return -1;
}

static (int flags, uint entryToken) ReadCliHeader(byte[] pe)
{
    int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
    int coff = e_lfanew + 4;
    int opt = coff + 20;
    ushort magic = BitConverter.ToUInt16(pe, opt);
    int ddBase = opt + (magic == 0x20B ? 112 : 96);
    int numDirs = BitConverter.ToInt32(pe, ddBase > 0 ? opt + (magic == 0x20B ? 108 : 92) : 0);
    if (numDirs <= 14) return (-1, 0);
    int rva = BitConverter.ToInt32(pe, ddBase + 14 * 8);
    int size = BitConverter.ToInt32(pe, ddBase + 14 * 8 + 4);
    if (rva <= 0 || size < 24) return (-1, 0);
    int off = RvaToOffset(pe, rva);
    if (off < 0 || off + 24 > pe.Length) return (-1, 0);
    if (BitConverter.ToInt32(pe, off) < 24) return (-1, 0); // cb
    return (BitConverter.ToInt32(pe, off + 16), BitConverter.ToUInt32(pe, off + 20));
}

static string TokenFromBlob(byte[] blob)
{
    // afPublicKey set -> blob is the full public key; the token is the last
    // 8 bytes of its SHA-1, reversed. Otherwise the blob IS the token.
    if (blob.Length > 8)
    {
        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(blob);
        Array.Reverse(hash);
        var tail = hash[0..8];
        return Convert.ToHexString(tail).ToLowerInvariant();
    }
    return Convert.ToHexString(blob).ToLowerInvariant();
}

static Dictionary<string, object> DumpOne(string path)
{
    var rec = new Dictionary<string, object> { ["file"] = path };
    try
    {
        byte[] raw = File.ReadAllBytes(path);
        var (flags, entryToken) = ReadCliHeader(raw);
        if (flags < 0)
        {
            rec["status"] = "no_cor20";
            return rec;
        }
        using var fs = File.OpenRead(path);
        using var pe = new PEReader(fs);
        if (!pe.HasMetadata)
        {
            rec["status"] = "not_managed";
            return rec;
        }
        var md = pe.GetMetadataReader();
        rec["status"] = "managed";
        var flagNames = new (int bit, string name)[] {
            (0x1, "ILONLY"), (0x2, "32BITREQUIRED"), (0x4, "IL_LIBRARY"),
            (0x8, "STRONGNAMESIGNED"), (0x10, "NATIVE_ENTRYPOINT"),
            (0x10000, "TRACKDEBUGDATA"), (0x20000, "32BITPREFERRED") };
        rec["cli_flags"] = flagNames.Where(f => (flags & f.bit) != 0).Select(f => f.name).OrderBy(s => s).ToArray();
        rec["cli_flags_value"] = flags;
        rec["entry_point_token"] = $"0x{entryToken:x8}";
        rec["metadata_version"] = md.MetadataVersion;
        var mod = md.GetModuleDefinition();
        rec["mvid"] = md.GetGuid(mod.Mvid).ToString().ToUpperInvariant();
        rec["module_name"] = md.GetString(mod.Name);
        try
        {
            var asm = md.GetAssemblyDefinition();
            rec["name"] = md.GetString(asm.Name);
            rec["version"] = asm.Version.ToString();
            var culture = md.GetString(asm.Culture);
            rec["culture"] = string.IsNullOrEmpty(culture) ? "neutral" : culture;
            rec["hash_algorithm"] = asm.HashAlgorithm.ToString();
            rec["hash_algorithm_value"] = (int)asm.HashAlgorithm;
            rec["public_key_token"] = TokenFromBlob(md.GetBlobBytes(asm.PublicKey));
            rec["assembly_flags"] = (int)asm.Flags;
            var tf = new List<string>();
            foreach (var h in asm.GetCustomAttributes())
            {
                var ca = md.GetCustomAttribute(h);
                if (ca.Constructor.Kind != HandleKind.MemberReference) continue;
                var mr = md.GetMemberReference((MemberReferenceHandle)ca.Constructor);
                if (mr.Parent.Kind != HandleKind.TypeReference) continue;
                var tr = md.GetTypeReference((TypeReferenceHandle)mr.Parent);
                if (md.GetString(tr.Name) != "TargetFrameworkAttribute") continue;
                if (md.GetString(tr.Namespace) != "System.Runtime.Versioning") continue;
                var reader = md.GetBlobReader(ca.Value);
                reader.ReadInt16(); // prolog
                var s = reader.ReadSerializedString();
                if (s is not null) tf.Add(s);
            }
            rec["target_framework"] = tf;
        }
        catch (BadImageFormatException)
        {
            rec["name"] = null; // netmodule: no Assembly table
        }
        var refs = new List<Dictionary<string, object>>();
        foreach (var h in md.AssemblyReferences)
        {
            var ar = md.GetAssemblyReference(h);
            refs.Add(new Dictionary<string, object>
            {
                ["name"] = md.GetString(ar.Name),
                ["version"] = ar.Version.ToString(),
                ["public_key_token"] = TokenFromBlob(md.GetBlobBytes(ar.PublicKeyOrToken)),
                ["culture"] = md.GetString(ar.Culture),
                ["flags"] = (int)ar.Flags,
            });
        }
        rec["assembly_refs"] = refs.OrderBy(r => (string)r["name"]).ToArray();
        var mrefs = new List<string>();
        int moduleRefCount = md.GetTableRowCount(TableIndex.ModuleRef);
        for (int i = 1; i <= moduleRefCount; i++)
        {
            var h = MetadataTokens.ModuleReferenceHandle(i);
            mrefs.Add(md.GetString(md.GetModuleReference(h).Name));
        }
        rec["module_refs"] = mrefs.OrderBy(s => s).ToArray();
        var pinvokes = new List<Dictionary<string, object>>();
        foreach (var h in md.MethodDefinitions)
        {
            var m = md.GetMethodDefinition(h);
            var import = m.GetImport();
            if (import.Name.IsNil) continue;
            pinvokes.Add(new Dictionary<string, object>
            {
                ["module"] = md.GetString(md.GetModuleReference(import.Module).Name),
                ["entry_point"] = md.GetString(import.Name),
                ["method"] = md.GetString(m.Name),
            });
        }
        rec["pinvoke"] = pinvokes.OrderBy(p => (string)p["module"] + ":" + (string)p["entry_point"]).ToArray();
        rec["counts"] = new Dictionary<string, int>
        {
            ["typedef"] = md.TypeDefinitions.Count,
            ["methoddef"] = md.MethodDefinitions.Count,
            ["field"] = md.FieldDefinitions.Count,
            ["typeref"] = md.TypeReferences.Count,
            ["memberref"] = md.MemberReferences.Count,
            ["assembly_ref"] = md.AssemblyReferences.Count,
            ["module_ref"] = moduleRefCount,
            ["implmap"] = md.GetTableRowCount(TableIndex.ImplMap),
        };
    }
    catch (Exception ex)
    {
        rec["status"] = "error";
        rec["error"] = ex.GetType().Name + ": " + ex.Message;
    }
    return rec;
}

if (args.Length == 0)
{
    Console.Error.WriteLine("usage: gtdotnet <file-or-dir> [more...]");
    return 2;
}
var files = new List<string>();
foreach (var arg in args)
{
    if (Directory.Exists(arg))
        files.AddRange(Directory.EnumerateFiles(arg, "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                     || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)));
    else files.Add(arg);
}
var opts = new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
foreach (var f in files.OrderBy(f => f))
{
    Console.WriteLine(JsonSerializer.Serialize(DumpOne(f), opts));
}
return 0;
