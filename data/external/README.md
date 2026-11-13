# Reference catalogs

`documentation.json` is a small, curated starting catalog with source URLs.
It covers switches, not positional subcommands or every version/abbreviation of
Windows tools. Expand it for the binaries and versions in your environment.

`filesec_extensions.json` contains the historical Appendix B snapshot. F8/F9
code extensions are removed from F10 to avoid counting the same class twice.

`lots_domains.json` is the MISP-maintained LOTS list, with upstream provenance.
It is an indicator of potentially abused trusted hosting, not a malware verdict.

`signatures.json` is an exact SHA256 lookup. An empty file is intentional: no
signature facts are invented for the real binaries in your environment. Format:

```text
{
  "<actual 64-character SHA256>": {
    "signer": "CN=Microsoft Windows, O=Microsoft Corporation",
    "signature_valid": true,
    "original_file_name": "cmd.exe"
  }
}
```

Only populate these records from trusted signature validation or EDR evidence.
`pefile` extracts OriginalFilename; it cannot establish Authenticode validity.
The optional upstream `xcyclopedia.json` uses exact hashes and its recorded
signature status (PowerShell enum 0=Valid). It is a historical observation,
not fresh revocation validation. Captured help output supplies approximate
documentation; manual records can extend that documentation. Explicit log
signature facts override reference facts. Manual hash entries override upstream
reference entries.

Run `python download_datasets.py --references` to fetch xCyclopedia and update
the LOTS mirror. Full upstream catalogs are optional downloads, not bundled
with this source tree. The live Filesec and LOTS websites may be unavailable;
the historical extension snapshot and MISP mirror support offline extraction.
