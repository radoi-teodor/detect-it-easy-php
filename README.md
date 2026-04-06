# DetectItEasy-PHP

A powerful, cross-platform file type detection and analysis library for PHP. Designed for cybersecurity experts, malware analysts, and reverse engineers.

Inspired by [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy), this pure PHP library identifies file formats, compilers, packers, protectors, installers, and frameworks through a combination of signature matching and heuristic analysis.

## Features

- **Universal format detection** — PE, ELF, Mach-O, APK, IPA, DEX, ZIP, RAR, 7z, PDF, Office documents, images, and 30+ more formats
- **Deep binary analysis** — PE header parsing (COFF, optional header, sections, Rich header), ELF header/section parsing, Mach-O load command parsing
- **Packer detection** — UPX, ASPack, PECompact, MPRESS, Petite, FSG, NSPack, PyInstaller, and more
- **Compiler identification** — MSVC (2005–2022), GCC, Clang/LLVM, Borland Delphi, Go, Rust, Nim, Zig, Free Pascal, and more
- **Protector detection** — Themida, VMProtect, Armadillo, Enigma, Code Virtualizer, .NET Reactor, ConfuserEx, and more
- **Installer detection** — NSIS, Inno Setup, InstallShield, WiX, and more
- **Framework detection** — .NET, Qt, Electron, Flutter, React Native, Xamarin, UIKit, AppKit
- **Entropy analysis** — Shannon entropy computation with block-level analysis for identifying packed/encrypted content
- **ZIP subtype refinement** — Automatically distinguishes APK, JAR, WAR, IPA, DOCX, XLSX, PPTX, EPUB, NuGet from plain ZIP
- **Rich header analysis** — Decodes PE Rich headers to identify Microsoft build tools
- **Extensible signature database** — JSON-based signatures, easy to add custom signatures
- **CLI tool included** — Batch scan directories, JSON output, quick scan mode
- **Cross-platform** — Runs on Windows, Linux, and macOS
- **PHP 7.4+** compatible (including PHP 8.x)

## Requirements

- PHP 7.4 or higher
- `ext-json` (included by default in PHP)

No external dependencies required.

## Installation

### Via Composer

```bash
composer require edimemune/detect-it-easy-php
```

### Manual Installation

Clone or download the repository:

```bash
git clone https://github.com/edimemune/detect-it-easy-php.git
cd detect-it-easy-php
composer install
```

## Quick Start

### Basic Usage (Library)

```php
<?php

require 'vendor/autoload.php';

use DetectItEasy\DetectItEasy;

$die = new DetectItEasy();

// Analyze a file
$result = $die->analyze('/path/to/suspicious.exe');

// Get the detected format
echo $result->getFileFormat();        // "PE" or "PE64"
echo $result->getFormatDescription(); // "Windows PE Executable (64-bit)"
echo $result->getMimeType();          // "application/vnd.microsoft.portable-executable"

// Check detections
foreach ($result->getDetections() as $category => $items) {
    foreach ($items as $detection) {
        echo "{$category}: {$detection['name']} {$detection['version']} ";
        echo "({$detection['confidence']})\n";
    }
}
// Example output:
//   compiler: Microsoft Visual C++ 2022 (0.9)
//   packer: UPX 3.96 (0.95)
//   protector: Themida (0.9)

// Check if the file appears packed
if ($result->isPacked()) {
    echo "Warning: File appears to be packed or protected!\n";
}

// Get entropy analysis
$entropy = $result->getEntropy();
echo "Entropy: {$entropy['overall']} / 8.0 ({$entropy['assessment']})\n";

// Get metadata (architecture, sections, timestamps, etc.)
$meta = $result->getMetadata();
echo "Machine: " . ($meta['machine'] ?? 'N/A') . "\n";
echo "Sections: " . ($meta['sections_count'] ?? 'N/A') . "\n";

// Full human-readable summary
echo $result->getSummary();

// JSON output
echo $result->toJson(JSON_PRETTY_PRINT);
```

### Quick Scan (Format Only)

```php
// Skip deep analysis and entropy — just identify the format
$result = $die->quickScan('/path/to/file.bin');
echo $result->getFileFormat(); // "ELF"
```

### Analyze Raw Data

```php
// Analyze binary data directly (no file needed)
$binaryData = file_get_contents('http://example.com/sample.bin');
$result = $die->analyzeData($binaryData, 'remote_sample.bin');
```

### Batch Analysis

```php
$files = glob('/malware-samples/*.exe');
$results = $die->batchAnalyze($files);

foreach ($results as $path => $result) {
    if ($result->hasError()) {
        echo "Error: {$result->getError()}\n";
        continue;
    }
    echo "{$path}: {$result->getFileFormat()}";
    if ($result->isPacked()) {
        echo " [PACKED]";
    }
    echo "\n";
}
```

### Configuration Options

```php
$die = new DetectItEasy([
    'signatures_path' => '/custom/signatures', // Custom signature database path
    'deep_scan'       => true,                  // Enable deep heuristic analysis
    'entropy_analysis' => true,                 // Enable entropy analysis
    'max_read_size'   => 10 * 1024 * 1024,     // Max bytes to read (10 MB)
]);
```

## CLI Usage

A command-line tool is included at `bin/die-php`:

```bash
# Analyze a single file
php bin/die-php malware.exe

# JSON output
php bin/die-php suspicious.bin --json

# Quick scan (format detection only)
php bin/die-php file.bin --quick

# Batch scan a directory
php bin/die-php /path/to/samples/ --batch

# Batch scan with JSON output
php bin/die-php /samples/ --batch --json

# Skip entropy analysis
php bin/die-php large_file.iso --no-entropy
```

### Example CLI Output

```
File: malware.exe
Size: 1.45 MB
Format: Windows PE Executable (64-bit)
Compiler: Microsoft Visual C++ 2019 (85%)
Packer: UPX (95%)
Entropy: 7.4523 / 8.0
** File appears to be packed/protected **
```

### Example JSON Output

```json
{
    "file": "malware.exe",
    "size": 1520435,
    "format": "PE64",
    "description": "Windows PE Executable (64-bit)",
    "mime_type": "application/vnd.microsoft.portable-executable",
    "packed": true,
    "detections": {
        "compiler": [
            {
                "name": "Microsoft Visual C++",
                "version": "2019",
                "confidence": 0.85,
                "extra": {"method": "linker_version"}
            }
        ],
        "packer": [
            {
                "name": "UPX",
                "version": "",
                "confidence": 0.95,
                "extra": {"method": "section_names"}
            }
        ]
    },
    "entropy": {
        "overall": 7.4523,
        "min": 3.2100,
        "max": 7.9800,
        "assessment": "very_high_likely_packed"
    },
    "metadata": {
        "machine": "AMD64 (x86-64)",
        "is_64bit": true,
        "subsystem": "Windows Console",
        "entry_point": "0x00015A30",
        "sections_count": 4,
        "rich_header": true
    }
}
```

## Supported Formats

### Executables
| Format | Detection | Deep Scan |
|--------|-----------|-----------|
| PE (Windows .exe/.dll) | Magic bytes + PE signature | Sections, Rich header, imports, compilers, packers, protectors |
| ELF (Linux) | Magic bytes | Sections, compilers, packers, stripped/debug detection |
| Mach-O (macOS/iOS) | Magic bytes (all variants) | Load commands, platform/SDK version, UUID, compilers |
| Mach-O Universal (Fat Binary) | Magic bytes | Multi-architecture analysis |
| DEX (Android Dalvik) | Magic bytes | - |
| MS-DOS | PE fallback | - |
| WebAssembly (.wasm) | Magic bytes | - |
| Java Class | Magic bytes | - |
| Python Bytecode (.pyc) | Magic bytes | - |

### Archives & Containers
| Format | Detection | Deep Scan |
|--------|-----------|-----------|
| ZIP | Magic bytes | Subtype refinement (APK, JAR, IPA, DOCX, etc.) |
| APK (Android) | ZIP + AndroidManifest.xml | Kotlin, Flutter, React Native, Xamarin, native libs |
| JAR (Java) | ZIP + MANIFEST.MF | WAR/EAR distinction |
| IPA (iOS) | ZIP + Payload/*.app | - |
| DOCX/XLSX/PPTX | ZIP + [Content_Types].xml | Office type detection |
| EPUB | ZIP + container.xml | - |
| RAR (v4/v5) | Magic bytes | Version, encryption detection |
| 7-Zip | Magic bytes | Version |
| GZIP | Magic bytes | Original filename, tar.gz detection |
| BZIP2 | Magic bytes | Block size |
| XZ | Magic bytes | - |
| CAB | Magic bytes | Version, file count |
| ACE | Magic bytes | - |
| ARJ | Magic bytes | - |
| ISO 9660 | Magic bytes at 0x8001 | - |

### Documents & Media
| Format | Detection |
|--------|-----------|
| PDF | Magic bytes |
| CFBF (OLE/legacy Office) | Magic bytes |
| PNG | Magic bytes |
| JPEG | Magic bytes |
| GIF (87a/89a) | Magic bytes |
| BMP | Magic bytes |
| RIFF (WAV/AVI) | Magic bytes |
| SQLite | Magic bytes |

## Custom Signatures

The signature database uses JSON files in the `signatures/` directory. You can add custom signatures:

```json
[
    {
        "name": "MyCustomPacker",
        "version": "1.0",
        "category": "packer",
        "confidence": 0.9,
        "strings": [
            {"value": "MyPackerSignature"}
        ],
        "hex_patterns": [
            {"bytes": "4D 59 50 4B ?? ?? 01 00", "offset": 0}
        ]
    }
]
```

Save as `signatures/pe_packers.json` (or whichever format + category). Hex patterns support `??` wildcards.

You can also point to a custom signatures directory:

```php
$die = new DetectItEasy([
    'signatures_path' => '/my/custom/signatures',
]);
```

## Architecture

```
src/
├── DetectItEasy.php              # Main entry point & orchestrator
├── Result/
│   └── AnalysisResult.php        # Structured result object
├── Scanner/
│   ├── ScannerInterface.php      # Scanner contract
│   ├── AbstractScanner.php       # Shared binary parsing utilities
│   ├── MagicBytesScanner.php     # Format identification (30+ formats)
│   ├── PEScanner.php             # PE deep analysis (headers, Rich, imports)
│   ├── ELFScanner.php            # ELF deep analysis (headers, sections)
│   ├── MachOScanner.php          # Mach-O deep analysis (load commands, fat)
│   └── ArchiveScanner.php        # Archive analysis (ZIP subtypes, metadata)
├── Signature/
│   └── SignatureDatabase.php     # JSON signature loader with caching
└── Heuristic/
    └── EntropyAnalyzer.php       # Shannon entropy analysis
signatures/
├── magic_bytes.json
├── pe_compilers.json
├── pe_packers.json
├── pe_protectors.json
├── pe_linkers.json
├── pe_installers.json
├── pe_libraries.json
├── elf_compilers.json
├── elf_packers.json
├── elf_protectors.json
├── macho_compilers.json
└── macho_packers.json
```

## Testing

```bash
composer install
./vendor/bin/phpunit
```

## License

MIT License. See [LICENSE](LICENSE) for details.
