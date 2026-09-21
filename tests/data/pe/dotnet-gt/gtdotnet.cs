// Ground-truth dumper for blint W3.1 (ground rule 29): reads managed PE
// metadata with System.Reflection.Metadata plus a spec-based byte-level walk
// of the CLI header, and prints one JSON line per file. Fields mirror blint's
// dotnet block contract (03/A.1): assembly identity, public key token,
// AssemblyRef list, ModuleRefs, P/Invoke surface, entry point, CLI flags,
// target framework.
//
// W3.2 additions (03/A.2), the fields the managed-capability packet adds:
//   - typerefs: the TypeRef table in row order, each row's ResolutionScope
//     resolved transitively to the assembly (or netmodule) that provides the
//     type. Rendering contract shared with blint, see resolve_typeref_scope.
//   - memberrefs: the MemberRef table in row order, each row's
//     MemberRefParent rendered the way blint renders it.
//   - user_strings: a spec-based walk of the #US heap (SRM has no enumerator
//     for it), reporting the decoded-entry count and a SHA-256 over the
//     decoded values in heap order — the same walk blint does, coded
//     independently in another language on the oracle side.
// The walk caps below must stay identical to blint's pe_dotnet constants so
// a capped walk hashes the same prefix on both sides.
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

static (int flags, uint entryToken, int snRva, int snSize) ReadCliHeader(byte[] pe)
{
    int e_lfanew = BitConverter.ToInt32(pe, 0x3C);
    int coff = e_lfanew + 4;
    int opt = coff + 20;
    ushort magic = BitConverter.ToUInt16(pe, opt);
    int ddBase = opt + (magic == 0x20B ? 112 : 96);
    int numDirs = BitConverter.ToInt32(pe, ddBase > 0 ? opt + (magic == 0x20B ? 108 : 92) : 0);
    if (numDirs <= 14) return (-1, 0, 0, 0);
    int rva = BitConverter.ToInt32(pe, ddBase + 14 * 8);
    int size = BitConverter.ToInt32(pe, ddBase + 14 * 8 + 4);
    if (rva <= 0 || size < 24) return (-1, 0, 0, 0);
    int off = RvaToOffset(pe, rva);
    if (off < 0 || off + 24 > pe.Length) return (-1, 0, 0, 0);
    if (BitConverter.ToInt32(pe, off) < 24) return (-1, 0, 0, 0); // cb
    // StrongNameSignature directory (II.25.3.3, offset 32): only when the
    // header declares itself long enough to carry it.
    int snRva = 0, snSize = 0;
    if (BitConverter.ToInt32(pe, off) >= 40 && off + 40 <= pe.Length)
    {
        snRva = BitConverter.ToInt32(pe, off + 32);
        snSize = BitConverter.ToInt32(pe, off + 36);
    }
    return (BitConverter.ToInt32(pe, off + 16), BitConverter.ToUInt32(pe, off + 20), snRva, snSize);
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

// The #US-walk caps, identical to blint/lib/pe_dotnet.py's constants so a
// capped walk hashes the same prefix on both sides (a hostile heap can only
// shorten both sides' result the same way).
//
// W3.4 additions (03/A.4), strong names — distinct from Authenticode, never
// merged with it:
//   - strong_name: the StrongNameSignature directory read from the CLI
//     header (RVA/size at offset 32, beside the ManagedNativeHeader at 64),
//     whether the bytes it names are all zero (the null signature a
//     delay-signed assembly ships), and whether the Assembly table declares
//     a public key. No verification: the oracle does not hash the assembly
//     and reports presence facts only.
//   - assembly_attributes: every assembly-level custom attribute's type full
//     name, sorted. This is the instrument that shows where DelaySign does
//     and does not live in real metadata (Roslyn consumes the
//     AssemblyDelaySignAttribute pseudo-attribute; any surviving row appears
//     here by name).
//   - ivt: InternalsVisibleToAttribute targets decoded from their blobs -
//     the friend assembly name and any PublicKey= the string names, plus
//     that key's token computed the same way blint computes it.
const int MAX_USER_STRINGS_WALKED = 262144;
const long MAX_USER_STRINGS_TOTAL_BYTES = 64L * 1024 * 1024;
const int MAX_US_ENTRY_BYTES = 1024 * 1024;

static string FullName(string ns, string name)
{
    return string.IsNullOrEmpty(ns) ? name : ns + "." + name;
}

// ResolutionScope resolved transitively to the providing assembly or
// netmodule: an AssemblyRef names the assembly, a ModuleRef or the Module
// row names a module of this assembly ("module:" prefix), a TypeRef is a
// nested type whose enclosing type is followed. Rendering contract shared
// with blint/lib/pe_dotnet.py — change both together.
static (string kind, string scope) ResolveTyperefScope(MetadataReader md, TypeReference tr)
{
    var current = tr;
    for (int depth = 0; depth < 8; depth++)
    {
        var scope = current.ResolutionScope;
        if (scope.IsNil) return ("nil", "");
        switch (scope.Kind)
        {
            case HandleKind.AssemblyReference:
                return ("assembly_ref",
                    md.GetString(md.GetAssemblyReference((AssemblyReferenceHandle)scope).Name));
            case HandleKind.ModuleReference:
                return ("module_ref",
                    "module:" + md.GetString(md.GetModuleReference((ModuleReferenceHandle)scope).Name));
            case HandleKind.ModuleDefinition:
                return ("module",
                    "module:" + md.GetString(md.GetModuleDefinition().Name));
            case HandleKind.TypeReference:
                int rid = MetadataTokens.GetRowNumber(md, scope);
                if (rid < 1) return ("nil", "");
                current = md.GetTypeReference(MetadataTokens.TypeReferenceHandle(rid));
                continue;
            default:
                return ("unresolved", "");
        }
    }
    return ("unresolved", "");
}

// MemberRefParent rendered the way blint renders it: a type parent renders
// as the full type name, a ModuleRef as "module:<name>", a MethodDef as
// "method:<name>", a TypeSpec (a signature blob, not a name) and a nil
// parent yield a row blint omits with a named degradation.
static (string kind, string parent) ResolveMemberrefParent(MetadataReader md, MemberReference mr)
{
    var parent = mr.Parent;
    switch (parent.Kind)
    {
        case HandleKind.TypeDefinition:
            var td = md.GetTypeDefinition((TypeDefinitionHandle)parent);
            return ("type_def", FullName(md.GetString(td.Namespace), md.GetString(td.Name)));
        case HandleKind.TypeReference:
            var tref = md.GetTypeReference((TypeReferenceHandle)parent);
            return ("type_ref", FullName(md.GetString(tref.Namespace), md.GetString(tref.Name)));
        case HandleKind.ModuleReference:
            return ("module_ref",
                "module:" + md.GetString(md.GetModuleReference((ModuleReferenceHandle)parent).Name));
        case HandleKind.MethodDefinition:
            return ("method_def",
                "method:" + md.GetString(md.GetMethodDefinition((MethodDefinitionHandle)parent).Name));
        case HandleKind.TypeSpecification:
            return ("type_spec", "");
        default:
            return ("nil", "");
    }
}

// Spec-based walk of the #US heap: every entry is a compressed byte count
// (which includes one trailing flag byte) followed by UTF-16LE bytes. The
// first heap byte is the empty string's entry. Returns the decoded-entry
// count and a SHA-256 over each value's UTF-8 bytes plus one 0x00
// separator, in heap order. Coded independently of blint's Python walk;
// both implement II.24.2.4 with the same caps.
static (int count, string sha256) WalkUserStrings(byte[] metadata, int rootOffset, int regionSize)
{
    int sig = BitConverter.ToInt32(metadata, rootOffset);
    if (sig != 0x424A5342) return (0, "");
    int versionLen = BitConverter.ToInt32(metadata, rootOffset + 12);
    // Signature(4) major(2) minor(2) reserved(4) length(4), version area,
    // then Flags(2) Streams(2) — the stream headers start right after.
    int pos = rootOffset + 16 + versionLen;
    if (pos + 4 > rootOffset + regionSize) return (0, "");
    int streamCount = BitConverter.ToInt16(metadata, pos + 2);
    pos += 4;
    int usOffset = -1, usSize = 0;
    for (int i = 0; i < streamCount && pos + 8 <= rootOffset + regionSize; i++)
    {
        int offset = BitConverter.ToInt32(metadata, pos);
        int size = BitConverter.ToInt32(metadata, pos + 4);
        pos += 8;
        int nul = Array.IndexOf(metadata, (byte)0, pos);
        if (nul < 0) break;
        string name = System.Text.Encoding.ASCII.GetString(metadata, pos, nul - pos);
        pos = nul + 1;
        // Stream names are padded to a 4-byte boundary from the root.
        pos += (4 - (pos - rootOffset) % 4) % 4;
        if (name == "#US") { usOffset = offset; usSize = size; }
    }
    if (usOffset < 0) return (0, "");
    int start = rootOffset + usOffset;
    int end = Math.Min(start + usSize, metadata.Length);
    int count = 0;
    long totalBytes = 0;
    using var sha = SHA256.Create();
    var utf8NoBom = new System.Text.UTF8Encoding(false);
    for (int p = start + 1; p < end && count < MAX_USER_STRINGS_WALKED;)
    {
        if (p >= end) break;
        byte first = metadata[p];
        int length, header;
        if ((first & 0x80) == 0) { length = first; header = 1; }
        else if ((first & 0xC0) == 0x80)
        {
            if (p + 2 > end) break;
            length = ((first & 0x3F) << 8) | metadata[p + 1]; header = 2;
        }
        else if ((first & 0xE0) == 0xC0)
        {
            if (p + 4 > end) break;
            length = ((first & 0x1F) << 24) | (metadata[p + 1] << 16)
                   | (metadata[p + 2] << 8) | metadata[p + 3];
            header = 4;
        }
        else break;
        if (length <= 0 || p + header + length > end) break;
        int payloadLen = length - 1;
        if (payloadLen > MAX_US_ENTRY_BYTES)
        {
            p += header + length;
            continue;
        }
        if (payloadLen % 2 == 1) payloadLen -= 1;
        string value = System.Text.Encoding.Unicode.GetString(
            metadata, p + header, payloadLen);
        byte[] utf8 = utf8NoBom.GetBytes(value);
        sha.TransformBlock(utf8, 0, utf8.Length, null, 0);
        sha.TransformBlock(new byte[] { 0 }, 0, 1, null, 0);
        count += 1;
        totalBytes += utf8.Length;
        if (totalBytes > MAX_USER_STRINGS_TOTAL_BYTES) break;
        p += header + length;
    }
    sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
    return (count, Convert.ToHexString(sha.Hash).ToLowerInvariant());
}

static Dictionary<string, object> DumpOne(string path)
{
    var rec = new Dictionary<string, object> { ["file"] = path };
    try
    {
        byte[] raw = File.ReadAllBytes(path);
        var (flags, entryToken, snRva, snSize) = ReadCliHeader(raw);
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
        byte[] asmPublicKey = Array.Empty<byte>();
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
            asmPublicKey = md.GetBlobBytes(asm.PublicKey);
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
        // W3.4: the strong-name block. CLI-header facts independent of the
        // Assembly table, so they dump for netmodules too. Presence facts
        // only — no hash, no verification.
        var sn = new Dictionary<string, object>
        {
            ["signature_rva"] = snRva,
            ["signature_size"] = snSize,
            ["signature_present"] = snRva > 0 && snSize > 0,
        };
        if (snRva > 0 && snSize > 0)
        {
            int snOff = RvaToOffset(raw, snRva);
            if (snOff < 0 || snOff + snSize > raw.Length)
            {
                sn["signature_all_zero"] = null; // unreadable: absent, not false
                sn["signature_readable"] = false;
            }
            else
            {
                sn["signature_readable"] = true;
                bool allZero = true;
                for (int i = 0; i < snSize; i++) if (raw[snOff + i] != 0) { allZero = false; break; }
                sn["signature_all_zero"] = allZero;
            }
        }
        // Assembly-level custom attributes: the full name of every one, plus
        // the decoded InternalsVisibleTo targets and the DelaySign row if it
        // survives compilation.
        var attrNames = new List<string>();
        var ivt = new List<Dictionary<string, object>>();
        bool? delaySignAttr = null;
        if (rec["status"].Equals("managed"))
        {
            try
            {
                var asmDef = md.GetAssemblyDefinition();
                foreach (var h in asmDef.GetCustomAttributes())
                {
                    var ca = md.GetCustomAttribute(h);
                    if (ca.Constructor.Kind != HandleKind.MemberReference) continue;
                    var mr = md.GetMemberReference((MemberReferenceHandle)ca.Constructor);
                    if (mr.Parent.Kind != HandleKind.TypeReference) continue;
                    var tr = md.GetTypeReference((TypeReferenceHandle)mr.Parent);
                    string attrName = FullName(md.GetString(tr.Namespace), md.GetString(tr.Name));
                    attrNames.Add(attrName);
                    if (attrName == "System.Runtime.CompilerServices.InternalsVisibleToAttribute")
                    {
                        var reader = md.GetBlobReader(ca.Value);
                        reader.ReadInt16(); // prolog
                        var s = reader.ReadSerializedString();
                        var entry = new Dictionary<string, object> { ["raw"] = s ?? "" };
                        // "Friend.Name" or "Friend.Name, PublicKey=<hex>"
                        var parts = (s ?? "").Split(',');
                        entry["name"] = parts[0].Trim();
                        foreach (var part in parts.Skip(1))
                        {
                            var kv = part.Trim();
                            if (kv.StartsWith("PublicKey=", StringComparison.OrdinalIgnoreCase))
                            {
                                string hex = kv.Substring(10).Replace(" ", "");
                                entry["public_key"] = hex.ToLowerInvariant();
                                byte[] keyBytes;
                                try { keyBytes = Convert.FromHexString(hex); }
                                catch { keyBytes = Array.Empty<byte>(); }
                                entry["public_key_token"] = keyBytes.Length >= 8 ? TokenFromBlob(keyBytes) : "";
                            }
                        }
                        ivt.Add(entry);
                    }
                    else if (attrName == "System.Reflection.AssemblyDelaySignAttribute")
                    {
                        var reader = md.GetBlobReader(ca.Value);
                        reader.ReadInt16(); // prolog
                        delaySignAttr = reader.ReadBoolean();
                    }
                }
            }
            catch (Exception) { /* netmodule-shaped or hostile: attribute facts absent */ }
        }
        sn["delay_sign_attribute"] = delaySignAttr;
        sn["declares_public_key"] = asmPublicKey.Length > 0;
        sn["public_key_size"] = asmPublicKey.Length;
        rec["strong_name"] = sn;
        rec["assembly_attributes"] = attrNames.OrderBy(s => s).ToArray();
        rec["ivt"] = ivt.ToArray();
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
        // W3.2: TypeRef table in row order with its ResolutionScope resolved.
        var trefs = new List<Dictionary<string, object>>();
        int trCount = md.TypeReferences.Count;
        for (int i = 1; i <= trCount; i++)
        {
            var tr = md.GetTypeReference(MetadataTokens.TypeReferenceHandle(i));
            var (kind, scope) = ResolveTyperefScope(md, tr);
            trefs.Add(new Dictionary<string, object>
            {
                ["name"] = FullName(md.GetString(tr.Namespace), md.GetString(tr.Name)),
                ["scope"] = scope,
                ["scope_kind"] = kind,
            });
        }
        rec["typerefs"] = trefs.ToArray();
        // W3.2: MemberRef table in row order with its MemberRefParent rendered.
        var mrefsOut = new List<Dictionary<string, object>>();
        int mrCount = md.MemberReferences.Count;
        for (int i = 1; i <= mrCount; i++)
        {
            var mr = md.GetMemberReference(MetadataTokens.MemberReferenceHandle(i));
            var (kind, parent) = ResolveMemberrefParent(md, mr);
            mrefsOut.Add(new Dictionary<string, object>
            {
                ["name"] = md.GetString(mr.Name),
                ["parent"] = parent,
                ["parent_kind"] = kind,
            });
        }
        rec["memberrefs"] = mrefsOut.ToArray();
        // W3.2: the #US walk (count + content hash), spec-based.
        var mdBytes = pe.GetMetadata().GetContent().ToArray();
        var (usCount, usHash) = WalkUserStrings(mdBytes, 0, mdBytes.Length);
        rec["user_strings_count"] = usCount;
        rec["user_strings_sha256"] = usHash;
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
