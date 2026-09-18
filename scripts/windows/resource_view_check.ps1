# Ground-rule-29 oracle: blint's resource/VERSIONINFO decode vs Windows' own
# view (W1.3).
#
# For every sample file this captures:
#   - `(Get-Item).VersionInfo` — Windows' own FileVersion/ProductVersion
#     strings (what Explorer shows).
#   - The Win32 resource tree, enumerated through the loader APIs
#     (EnumResourceTypes/EnumResourceNames/EnumResourceLanguages/
#     SizeofResource). The recursion runs in C# because PowerShell
#     scriptblock delegates cannot nest, and prints one "TYPE|ID|LANG|SIZE"
#     row per resource, which is what blint's tree summary is diffed against.
#
# Copy to the VM (from the mini):
#   scp scripts/windows/resource_view_check.ps1 win11-vm:C:/Users/appthreat/blint/
#   ssh win11-vm 'powershell -ExecutionPolicy Bypass -File C:\Users\appthreat\blint\resource_view_check.ps1'
param(
    [string]$SampleDir = "C:\Users\appthreat\blint-corpus\tier0-sample"
)
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class ResourceTree {
    delegate bool EnumResTypeProc(IntPtr hModule, IntPtr type, IntPtr param);
    delegate bool EnumResNameProc(IntPtr hModule, IntPtr type, IntPtr name, IntPtr param);
    delegate bool EnumResLangProc(IntPtr hModule, IntPtr type, IntPtr name, ushort lang, IntPtr param);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr LoadLibraryEx(string name, IntPtr hFile, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FreeLibrary(IntPtr hModule);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool EnumResourceTypes(IntPtr hModule, EnumResTypeProc cb, IntPtr param);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool EnumResourceNames(IntPtr hModule, IntPtr type, EnumResNameProc cb, IntPtr param);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool EnumResourceLanguages(IntPtr hModule, IntPtr type, IntPtr name, EnumResLangProc cb, IntPtr param);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint SizeofResource(IntPtr hModule, IntPtr resInfo);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr FindResourceEx(IntPtr hModule, IntPtr type, IntPtr name, ushort lang);

    static string ResolveId(IntPtr value) {
        if ((ulong)value >= 0x10000UL) {
            return Marshal.PtrToStringUni(value);
        }
        return ((ulong)value & 0xFFFF).ToString();
    }

    static List<string> rows = new List<string>();

    static bool OnLang(IntPtr hMod, IntPtr type, IntPtr name, ushort lang, IntPtr param) {
        IntPtr hRes = FindResourceEx(hMod, type, name, lang);
        uint size = (hRes == IntPtr.Zero) ? 0u : SizeofResource(hMod, hRes);
        rows.Add(type + "|" + ResolveId(name) + "|" + lang + "|" + size);
        return true;
    }

    static bool OnName(IntPtr hMod, IntPtr type, IntPtr name, IntPtr param) {
        EnumResLangProc cb = OnLang;
        EnumResourceLanguages(hMod, type, name, cb, IntPtr.Zero);
        return true;
    }

    static bool OnType(IntPtr hMod, IntPtr type, IntPtr param) {
        EnumResNameProc cb = OnName;
        EnumResourceNames(hMod, type, cb, IntPtr.Zero);
        return true;
    }

    public static string[] Enumerate(string file) {
        rows = new List<string>();
        IntPtr h = LoadLibraryEx(file, IntPtr.Zero, 0x2); // LOAD_LIBRARY_AS_DATAFILE
        if (h == IntPtr.Zero) {
            return new string[] { "LOAD_FAILED" };
        }
        EnumResTypeProc cb = OnType;
        EnumResourceTypes(h, cb, IntPtr.Zero);
        FreeLibrary(h);
        return rows.ToArray();
    }
}
"@

$summary = New-Object System.Collections.Generic.List[object]
Get-ChildItem -File $SampleDir -Include *.exe, *.dll, *.pyd -Recurse | ForEach-Object {
    $file = $_.FullName
    $rel = $file.Substring($SampleDir.Length).TrimStart("\", "/")
    $vi = (Get-Item -LiteralPath $file).VersionInfo
    $summary.Add([ordered]@{
        file         = $rel
        version_info = [ordered]@{
            file_version    = $vi.FileVersion
            product_version = $vi.ProductVersion
            company_name    = $vi.CompanyName
        }
        tree         = [ResourceTree]::Enumerate($file)
    })
}

$outPath = Join-Path $SampleDir "resource-view-windows.json"
$summary | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $outPath
Write-Host "== wrote $outPath"
