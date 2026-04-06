<?php

declare(strict_types=1);

namespace DetectItEasy\Scanner;

use DetectItEasy\Signature\SignatureDatabase;

/**
 * Identifies file format using magic byte signatures.
 */
class MagicBytesScanner
{
    /** @var SignatureDatabase */
    private $signatureDb;

    /**
     * Built-in magic bytes for the most common formats.
     * These are used as a fast path and fallback.
     *
     * @var array<int, array{bytes: string, offset: int, format: string, description: string, mime_type: string, check?: callable}>
     */
    private $builtinSignatures;

    public function __construct(SignatureDatabase $signatureDb)
    {
        $this->signatureDb = $signatureDb;
        $this->builtinSignatures = $this->getBuiltinSignatures();
    }

    /**
     * Scan data and identify the file format.
     *
     * @param string $data     Raw binary data.
     * @param int    $fileSize Total file size.
     * @return array{format: string, description: string, mime_type: string}|null
     */
    public function scan(string $data, int $fileSize): ?array
    {
        // Try built-in fast path first
        foreach ($this->builtinSignatures as $sig) {
            $offset = $sig['offset'];
            $bytes = $sig['bytes'];

            if ($offset + strlen($bytes) > strlen($data)) {
                continue;
            }

            if (substr($data, $offset, strlen($bytes)) === $bytes) {
                // Additional check callback if present
                if (isset($sig['check']) && !($sig['check'])($data, $fileSize)) {
                    continue;
                }
                return [
                    'format' => $sig['format'],
                    'description' => $sig['description'],
                    'mime_type' => $sig['mime_type'],
                ];
            }
        }

        // Fallback: check the JSON signature database
        $dbSignatures = $this->signatureDb->getMagicBytes();
        foreach ($dbSignatures as $sig) {
            $hexPattern = $sig['magic'] ?? '';
            $offset = $sig['offset'] ?? 0;

            if ($hexPattern === '') {
                continue;
            }

            if ($this->matchMagicHex($data, $hexPattern, $offset)) {
                return [
                    'format' => $sig['format'],
                    'description' => $sig['description'] ?? $sig['format'],
                    'mime_type' => $sig['mime_type'] ?? 'application/octet-stream',
                ];
            }
        }

        return null;
    }

    private function matchMagicHex(string $data, string $hexPattern, int $offset): bool
    {
        $bytes = @hex2bin(str_replace(' ', '', $hexPattern));
        if ($bytes === false) {
            return false;
        }
        if ($offset + strlen($bytes) > strlen($data)) {
            return false;
        }
        return substr($data, $offset, strlen($bytes)) === $bytes;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function getBuiltinSignatures(): array
    {
        return [
            // ---- Executables ----
            [
                'bytes' => "MZ",
                'offset' => 0,
                'format' => 'PE',
                'description' => 'Windows PE Executable',
                'mime_type' => 'application/vnd.microsoft.portable-executable',
                'check' => function (string $data, int $fileSize): bool {
                    // Verify PE signature at e_lfanew offset
                    if (strlen($data) < 64) {
                        return true; // Could be DOS stub only
                    }
                    $peOffset = unpack('V', substr($data, 0x3C, 4));
                    if ($peOffset && $peOffset[1] > 0 && $peOffset[1] < $fileSize) {
                        if ($peOffset[1] + 4 <= strlen($data)) {
                            $peSig = substr($data, $peOffset[1], 4);
                            return $peSig === "PE\x00\x00";
                        }
                    }
                    return true;
                },
            ],
            [
                'bytes' => "\x7FELF",
                'offset' => 0,
                'format' => 'ELF',
                'description' => 'ELF Executable',
                'mime_type' => 'application/x-elf',
                'check' => function (string $data): bool {
                    return strlen($data) >= 16;
                },
            ],
            // Mach-O magic numbers
            [
                'bytes' => "\xFE\xED\xFA\xCE",
                'offset' => 0,
                'format' => 'Mach-O',
                'description' => 'Mach-O Executable (32-bit)',
                'mime_type' => 'application/x-mach-binary',
            ],
            [
                'bytes' => "\xFE\xED\xFA\xCF",
                'offset' => 0,
                'format' => 'Mach-O 64',
                'description' => 'Mach-O Executable (64-bit)',
                'mime_type' => 'application/x-mach-binary',
            ],
            [
                'bytes' => "\xCE\xFA\xED\xFE",
                'offset' => 0,
                'format' => 'Mach-O',
                'description' => 'Mach-O Executable (32-bit, reverse byte order)',
                'mime_type' => 'application/x-mach-binary',
            ],
            [
                'bytes' => "\xCF\xFA\xED\xFE",
                'offset' => 0,
                'format' => 'Mach-O 64',
                'description' => 'Mach-O Executable (64-bit, reverse byte order)',
                'mime_type' => 'application/x-mach-binary',
            ],
            [
                'bytes' => "\xCA\xFE\xBA\xBE",
                'offset' => 0,
                'format' => 'Mach-O Universal',
                'description' => 'Mach-O Universal Binary (Fat Binary)',
                'mime_type' => 'application/x-mach-binary',
                'check' => function (string $data): bool {
                    // Distinguish from Java class files: fat binaries have a
                    // small number of architectures (nfat_arch), while Java
                    // class files have a large minor version at bytes 4-7.
                    if (strlen($data) < 8) {
                        return true;
                    }
                    $nfat = unpack('N', substr($data, 4, 4));
                    // A fat binary will have a small arch count (typically 1-4)
                    return $nfat && $nfat[1] > 0 && $nfat[1] < 20;
                },
            ],
            // Android DEX
            [
                'bytes' => "dex\n",
                'offset' => 0,
                'format' => 'DEX',
                'description' => 'Android Dalvik Executable',
                'mime_type' => 'application/x-dex',
            ],
            // MS-DOS COM (heuristic - INT 20h at start)
            // Omitted: too many false positives without deep analysis.

            // ---- Archives ----
            [
                'bytes' => "PK\x03\x04",
                'offset' => 0,
                'format' => 'ZIP',
                'description' => 'ZIP Archive',
                'mime_type' => 'application/zip',
                'check' => function (string $data): bool {
                    // Refine: detect APK, JAR, IPA, DOCX, XLSX, etc.
                    // This is handled in ArchiveScanner for deep scan.
                    return true;
                },
            ],
            [
                'bytes' => "PK\x05\x06",
                'offset' => 0,
                'format' => 'ZIP',
                'description' => 'ZIP Archive (empty)',
                'mime_type' => 'application/zip',
            ],
            [
                'bytes' => "Rar!\x1A\x07\x00",
                'offset' => 0,
                'format' => 'RAR',
                'description' => 'RAR Archive (v4)',
                'mime_type' => 'application/x-rar-compressed',
            ],
            [
                'bytes' => "Rar!\x1A\x07\x01\x00",
                'offset' => 0,
                'format' => 'RAR',
                'description' => 'RAR Archive (v5)',
                'mime_type' => 'application/x-rar-compressed',
            ],
            [
                'bytes' => "7z\xBC\xAF\x27\x1C",
                'offset' => 0,
                'format' => '7z',
                'description' => '7-Zip Archive',
                'mime_type' => 'application/x-7z-compressed',
            ],
            [
                'bytes' => "\x1F\x8B",
                'offset' => 0,
                'format' => 'GZIP',
                'description' => 'GZIP Compressed',
                'mime_type' => 'application/gzip',
            ],
            [
                'bytes' => "BZ",
                'offset' => 0,
                'format' => 'BZIP2',
                'description' => 'BZIP2 Compressed',
                'mime_type' => 'application/x-bzip2',
                'check' => function (string $data): bool {
                    return strlen($data) >= 3 && $data[2] === 'h';
                },
            ],
            [
                'bytes' => "\xFD\x37\x7A\x58\x5A\x00",
                'offset' => 0,
                'format' => 'XZ',
                'description' => 'XZ Compressed',
                'mime_type' => 'application/x-xz',
            ],
            [
                'bytes' => "MSCF",
                'offset' => 0,
                'format' => 'CAB',
                'description' => 'Microsoft Cabinet Archive',
                'mime_type' => 'application/vnd.ms-cab-compressed',
            ],
            [
                'bytes' => "\x60\xEA",
                'offset' => 0,
                'format' => 'ARJ',
                'description' => 'ARJ Archive',
                'mime_type' => 'application/x-arj',
            ],
            [
                'bytes' => "**ACE**",
                'offset' => 7,
                'format' => 'ACE',
                'description' => 'ACE Archive',
                'mime_type' => 'application/x-ace-compressed',
            ],

            // ---- Documents ----
            [
                'bytes' => "%PDF",
                'offset' => 0,
                'format' => 'PDF',
                'description' => 'PDF Document',
                'mime_type' => 'application/pdf',
            ],
            [
                'bytes' => "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
                'offset' => 0,
                'format' => 'CFBF',
                'description' => 'Compound File Binary Format (MS Office legacy/OLE)',
                'mime_type' => 'application/x-cfb',
            ],

            // ---- Images ----
            [
                'bytes' => "\x89PNG\r\n\x1A\n",
                'offset' => 0,
                'format' => 'PNG',
                'description' => 'PNG Image',
                'mime_type' => 'image/png',
            ],
            [
                'bytes' => "\xFF\xD8\xFF",
                'offset' => 0,
                'format' => 'JPEG',
                'description' => 'JPEG Image',
                'mime_type' => 'image/jpeg',
            ],
            [
                'bytes' => "GIF87a",
                'offset' => 0,
                'format' => 'GIF',
                'description' => 'GIF Image (87a)',
                'mime_type' => 'image/gif',
            ],
            [
                'bytes' => "GIF89a",
                'offset' => 0,
                'format' => 'GIF',
                'description' => 'GIF Image (89a)',
                'mime_type' => 'image/gif',
            ],
            [
                'bytes' => "BM",
                'offset' => 0,
                'format' => 'BMP',
                'description' => 'BMP Image',
                'mime_type' => 'image/bmp',
            ],
            [
                'bytes' => "RIFF",
                'offset' => 0,
                'format' => 'RIFF',
                'description' => 'RIFF Container',
                'mime_type' => 'application/octet-stream',
                'check' => function (string $data): bool {
                    return strlen($data) >= 12;
                },
            ],

            // ---- Disk images ----
            [
                'bytes' => "CD001",
                'offset' => 0x8001,
                'format' => 'ISO9660',
                'description' => 'ISO 9660 Disc Image',
                'mime_type' => 'application/x-iso9660-image',
            ],

            // ---- Java ----
            [
                'bytes' => "\xCA\xFE\xBA\xBE",
                'offset' => 0,
                'format' => 'JavaClass',
                'description' => 'Java Class File',
                'mime_type' => 'application/x-java-applet',
                'check' => function (string $data): bool {
                    // Distinguish from Mach-O fat binary
                    if (strlen($data) < 8) {
                        return false;
                    }
                    $minorVersion = unpack('N', substr($data, 4, 4));
                    // Java class files have version >= 45.0
                    return $minorVersion && $minorVersion[1] >= 44;
                },
            ],

            // ---- Python ----
            // PYC magic varies by version; we detect common ones
            [
                'bytes' => "\x42\x0D\x0D\x0A",
                'offset' => 0,
                'format' => 'PYC',
                'description' => 'Python 3.7+ Bytecode',
                'mime_type' => 'application/x-python-bytecode',
            ],

            // ---- WebAssembly ----
            [
                'bytes' => "\x00asm",
                'offset' => 0,
                'format' => 'WASM',
                'description' => 'WebAssembly Binary',
                'mime_type' => 'application/wasm',
            ],

            // ---- Firmware / ROM ----
            [
                'bytes' => "\x7FCGB",
                'offset' => 0x104,
                'format' => 'GBC ROM',
                'description' => 'Game Boy Color ROM',
                'mime_type' => 'application/octet-stream',
            ],

            // ---- SQLite ----
            [
                'bytes' => "SQLite format 3\x00",
                'offset' => 0,
                'format' => 'SQLite',
                'description' => 'SQLite 3 Database',
                'mime_type' => 'application/x-sqlite3',
            ],
        ];
    }
}
