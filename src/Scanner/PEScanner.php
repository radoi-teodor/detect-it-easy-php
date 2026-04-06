<?php

declare(strict_types=1);

namespace DetectItEasy\Scanner;

use DetectItEasy\Result\AnalysisResult;

/**
 * Deep scanner for Windows PE (Portable Executable) files.
 *
 * Detects compilers, packers, protectors, linkers, and other tools
 * by analyzing PE headers, section characteristics, imports, and
 * embedded strings.
 */
class PEScanner extends AbstractScanner
{
    // PE constants
    private const IMAGE_FILE_MACHINE_I386  = 0x014C;
    private const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    private const IMAGE_FILE_MACHINE_ARM   = 0x01C0;
    private const IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

    private const IMAGE_SUBSYSTEM_NATIVE                  = 1;
    private const IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2;
    private const IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3;
    private const IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10;
    private const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16;

    public function deepScan(string $data, int $fileSize, AnalysisResult $result): void
    {
        if (strlen($data) < 64) {
            return;
        }

        // Parse PE header
        $peOffset = $this->readUint32LE($data, 0x3C);
        if ($peOffset === 0 || $peOffset + 24 > strlen($data)) {
            $result->setMetadata('sub_format', 'MS-DOS');
            $result->setFileFormat([
                'format' => 'MS-DOS',
                'description' => 'MS-DOS Executable (no PE header)',
                'mime_type' => 'application/x-dosexec',
            ]);
            return;
        }

        $peSig = substr($data, $peOffset, 4);
        if ($peSig !== "PE\x00\x00") {
            return;
        }

        // COFF header
        $coffOffset = $peOffset + 4;
        $machine = $this->readUint16LE($data, $coffOffset);
        $numberOfSections = $this->readUint16LE($data, $coffOffset + 2);
        $timeDateStamp = $this->readUint32LE($data, $coffOffset + 4);
        $sizeOfOptionalHeader = $this->readUint16LE($data, $coffOffset + 16);
        $characteristics = $this->readUint16LE($data, $coffOffset + 18);

        // Optional header
        $optOffset = $coffOffset + 20;
        if ($optOffset + 2 > strlen($data)) {
            return;
        }
        $magic = $this->readUint16LE($data, $optOffset);
        $is64 = ($magic === 0x020B); // PE32+

        // Update format to PE64 if applicable
        if ($is64) {
            $result->setFileFormat([
                'format' => 'PE64',
                'description' => 'Windows PE Executable (64-bit)',
                'mime_type' => 'application/vnd.microsoft.portable-executable',
            ]);
        }

        // Metadata
        $result->setMetadata('machine', $this->getMachineName($machine));
        $result->setMetadata('sections_count', $numberOfSections);
        $result->setMetadata('timestamp', $timeDateStamp);
        $result->setMetadata('timestamp_date', $timeDateStamp > 0 ? date('Y-m-d H:i:s', $timeDateStamp) : null);
        $result->setMetadata('is_64bit', $is64);
        $result->setMetadata('is_dll', ($characteristics & 0x2000) !== 0);
        $result->setMetadata('is_system', ($characteristics & 0x1000) !== 0);

        // Linker version
        if ($optOffset + 3 <= strlen($data)) {
            $linkerMajor = ord($data[$optOffset + 2]);
            $linkerMinor = ord($data[$optOffset + 3]);
            $result->setMetadata('linker_version', "{$linkerMajor}.{$linkerMinor}");
        }

        // Subsystem
        $subsystemOffset = $is64 ? $optOffset + 68 : $optOffset + 64;
        if ($subsystemOffset + 2 <= strlen($data)) {
            $subsystem = $this->readUint16LE($data, $subsystemOffset);
            $result->setMetadata('subsystem', $this->getSubsystemName($subsystem));
        }

        // Entry point
        $epOffset = $optOffset + 16;
        if ($epOffset + 4 <= strlen($data)) {
            $entryPoint = $this->readUint32LE($data, $epOffset);
            $result->setMetadata('entry_point', sprintf('0x%08X', $entryPoint));
        }

        // Parse sections
        $sectionTableOffset = $optOffset + $sizeOfOptionalHeader;
        $sections = $this->parseSections($data, $sectionTableOffset, $numberOfSections);
        $result->setMetadata('sections', $sections);

        // Detect compiler/packer/protector from signatures
        $this->detectFromSignatures($data, $result);

        // Heuristic detection from PE structure
        $this->heuristicDetection($data, $result, $sections, $peOffset, $is64, $optOffset);

        // Rich header analysis
        $this->analyzeRichHeader($data, $peOffset, $result);

        // Import analysis
        $this->analyzeImports($data, $result, $is64, $optOffset);
    }

    /**
     * Parse PE section table.
     *
     * @return array<int, array<string, mixed>>
     */
    private function parseSections(string $data, int $offset, int $count): array
    {
        $sections = [];
        for ($i = 0; $i < $count; $i++) {
            $secOffset = $offset + ($i * 40);
            if ($secOffset + 40 > strlen($data)) {
                break;
            }

            $name = rtrim($this->readString($data, $secOffset, 8), "\0");
            $virtualSize = $this->readUint32LE($data, $secOffset + 8);
            $virtualAddress = $this->readUint32LE($data, $secOffset + 12);
            $rawDataSize = $this->readUint32LE($data, $secOffset + 16);
            $rawDataPointer = $this->readUint32LE($data, $secOffset + 20);
            $characteristics = $this->readUint32LE($data, $secOffset + 36);

            $sections[] = [
                'name' => $name,
                'virtual_size' => $virtualSize,
                'virtual_address' => sprintf('0x%08X', $virtualAddress),
                'raw_size' => $rawDataSize,
                'raw_offset' => sprintf('0x%08X', $rawDataPointer),
                'executable' => ($characteristics & 0x20000000) !== 0,
                'writable' => ($characteristics & 0x80000000) !== 0,
                'readable' => ($characteristics & 0x40000000) !== 0,
            ];
        }
        return $sections;
    }

    /**
     * Detect compilers, packers, and protectors using the signature database.
     */
    private function detectFromSignatures(string $data, AnalysisResult $result): void
    {
        $categories = ['compilers', 'packers', 'protectors', 'linkers', 'installers', 'libraries'];

        foreach ($categories as $category) {
            $signatures = $this->signatureDb->getSignatures('pe', $category);
            $matches = $this->matchSignatures($data, $signatures);

            foreach ($matches as $match) {
                $result->addDetection(
                    $match['category'] ?: rtrim($category, 's'),
                    $match['name'],
                    $match['version'],
                    $match['confidence']
                );
            }
        }
    }

    /**
     * Heuristic detection based on PE structure analysis.
     */
    private function heuristicDetection(
        string $data,
        AnalysisResult $result,
        array $sections,
        int $peOffset,
        bool $is64,
        int $optOffset
    ): void {
        $sectionNames = array_column($sections, 'name');

        // UPX detection: sections named UPX0, UPX1, UPX2
        if (in_array('UPX0', $sectionNames) || in_array('UPX1', $sectionNames)) {
            $result->addDetection('packer', 'UPX', '', 0.95, ['method' => 'section_names']);
        }

        // ASPack detection
        if (in_array('.aspack', $sectionNames) || in_array('.adata', $sectionNames)) {
            $result->addDetection('packer', 'ASPack', '', 0.9, ['method' => 'section_names']);
        }

        // PECompact
        if (in_array('pec1', $sectionNames) || in_array('pec2', $sectionNames) || in_array('PEC2', $sectionNames)) {
            $result->addDetection('packer', 'PECompact', '', 0.9, ['method' => 'section_names']);
        }

        // MPRESS
        if (in_array('.MPRESS1', $sectionNames) || in_array('.MPRESS2', $sectionNames)) {
            $result->addDetection('packer', 'MPRESS', '', 0.9, ['method' => 'section_names']);
        }

        // Themida / WinLicense
        if (in_array('.themida', $sectionNames) || in_array('.winlice', $sectionNames)) {
            $result->addDetection('protector', 'Themida/WinLicense', '', 0.9, ['method' => 'section_names']);
        }

        // VMProtect
        if (in_array('.vmp0', $sectionNames) || in_array('.vmp1', $sectionNames) || in_array('.vmp2', $sectionNames)) {
            $result->addDetection('protector', 'VMProtect', '', 0.95, ['method' => 'section_names']);
        }

        // Enigma Protector
        if (in_array('.enigma1', $sectionNames) || in_array('.enigma2', $sectionNames)) {
            $result->addDetection('protector', 'Enigma Protector', '', 0.9, ['method' => 'section_names']);
        }

        // .ndata / .nsis → NSIS installer
        if (in_array('.ndata', $sectionNames) || in_array('.nsis', $sectionNames)) {
            $result->addDetection('installer', 'NSIS (Nullsoft Scriptable Install System)', '', 0.9, ['method' => 'section_names']);
        }

        // Inno Setup
        if (strpos($data, 'Inno Setup') !== false) {
            $result->addDetection('installer', 'Inno Setup', '', 0.9, ['method' => 'string_match']);
        }

        // .NET detection
        if (strpos($data, '_CorExeMain') !== false || strpos($data, 'mscoree.dll') !== false) {
            $result->addDetection('compiler', 'Microsoft .NET', '', 0.95, ['method' => 'import_check']);
            $this->detectDotNetVersion($data, $result);
        }

        // Go binary detection
        if (strpos($data, 'Go build ID:') !== false || strpos($data, 'runtime.main') !== false) {
            $result->addDetection('compiler', 'Go (Golang)', '', 0.9, ['method' => 'string_match']);
        }

        // Rust detection
        if (strpos($data, 'rust_begin_unwind') !== false || strpos($data, '/rustc/') !== false) {
            $result->addDetection('compiler', 'Rust', '', 0.85, ['method' => 'string_match']);
        }

        // Delphi / Borland detection
        if (in_array('CODE', $sectionNames) && in_array('DATA', $sectionNames) && in_array('BSS', $sectionNames)) {
            $result->addDetection('compiler', 'Borland Delphi/C++ Builder', '', 0.7, ['method' => 'section_names']);
        }
        if (strpos($data, 'TObject') !== false && strpos($data, 'TForm') !== false) {
            $result->addDetection('compiler', 'Borland Delphi', '', 0.85, ['method' => 'string_match']);
        }

        // AutoIt detection
        if (strpos($data, '>>>AUTOIT SCRIPT<<<') !== false || strpos($data, 'AU3!EA06') !== false) {
            $result->addDetection('compiler', 'AutoIt', '', 0.95, ['method' => 'string_match']);
        }

        // PyInstaller detection
        if (strpos($data, 'pyi-runtime') !== false || strpos($data, 'PyInstaller') !== false) {
            $result->addDetection('packer', 'PyInstaller', '', 0.9, ['method' => 'string_match']);
        }

        // Electron / NWJS
        if (strpos($data, 'electron.asar') !== false || strpos($data, 'electron') !== false && strpos($data, 'node.dll') !== false) {
            $result->addDetection('framework', 'Electron', '', 0.8, ['method' => 'string_match']);
        }

        // Heuristic: writable + executable section is suspicious
        foreach ($sections as $sec) {
            if ($sec['executable'] && $sec['writable'] && $sec['name'] !== '.text') {
                $result->setMetadata('suspicious_section', $sec['name']);
            }
        }

        // Detect compiler from linker version heuristics
        $this->detectCompilerFromLinkerVersion($data, $result, $optOffset, $is64);
    }

    /**
     * Analyze the Rich header (Microsoft compiler/linker info).
     */
    private function analyzeRichHeader(string $data, int $peOffset, AnalysisResult $result): void
    {
        // The Rich header sits between the DOS stub and the PE signature
        $richPos = strpos($data, "Rich");
        if ($richPos === false || $richPos > $peOffset) {
            return;
        }

        // The Rich header is XOR-encrypted with a key at richPos+4
        if ($richPos + 8 > strlen($data)) {
            return;
        }

        $key = $this->readUint32LE($data, $richPos + 4);
        $result->setMetadata('rich_header', true);
        $result->setMetadata('rich_header_key', sprintf('0x%08X', $key));

        // Find "DanS" marker (XOR'd with key)
        $dansXor = pack('V', 0x536E6144 ^ $key); // "DanS" ^ key
        $dansPos = strpos(substr($data, 0, $richPos), $dansXor);

        if ($dansPos === false) {
            return;
        }

        // Decode Rich header entries
        $entries = [];
        $pos = $dansPos + 16; // Skip DanS + 3 padding DWORDs
        while ($pos + 8 <= $richPos) {
            $compId = $this->readUint32LE($data, $pos) ^ $key;
            $count = $this->readUint32LE($data, $pos + 4) ^ $key;

            $toolId = $compId >> 16;
            $buildId = $compId & 0xFFFF;

            if ($toolId > 0 || $buildId > 0) {
                $entries[] = [
                    'tool_id' => $toolId,
                    'build_id' => $buildId,
                    'count' => $count,
                    'tool_name' => $this->getRichToolName($toolId),
                ];
            }

            $pos += 8;
        }

        if (!empty($entries)) {
            $result->setMetadata('rich_header_entries', $entries);

            // Infer MSVC version from build IDs
            $this->inferMSVCVersion($entries, $result);
        }
    }

    /**
     * Detect .NET framework version from metadata.
     */
    private function detectDotNetVersion(string $data, AnalysisResult $result): void
    {
        // Look for version strings like "v4.0.30319" or "v2.0.50727"
        if (preg_match('/v(\d+\.\d+\.\d+)/', $data, $matches)) {
            $version = $matches[1];
            $result->setMetadata('dotnet_runtime', $version);
        }
    }

    /**
     * Detect compiler from PE optional header linker version.
     */
    private function detectCompilerFromLinkerVersion(string $data, AnalysisResult $result, int $optOffset, bool $is64): void
    {
        if ($optOffset + 3 >= strlen($data)) {
            return;
        }

        $major = ord($data[$optOffset + 2]);
        $minor = ord($data[$optOffset + 3]);

        // Known linker versions
        $linkerMap = [
            '14.0'  => ['Microsoft Visual C++ 2015', '2015'],
            '14.10' => ['Microsoft Visual C++ 2017', '2017'],
            '14.16' => ['Microsoft Visual C++ 2017', '2017 (15.9)'],
            '14.20' => ['Microsoft Visual C++ 2019', '2019'],
            '14.29' => ['Microsoft Visual C++ 2019', '2019 (16.11)'],
            '14.30' => ['Microsoft Visual C++ 2022', '2022'],
            '14.36' => ['Microsoft Visual C++ 2022', '2022 (17.6)'],
            '14.38' => ['Microsoft Visual C++ 2022', '2022 (17.8)'],
            '14.40' => ['Microsoft Visual C++ 2022', '2022 (17.10)'],
            '12.0'  => ['Microsoft Visual C++ 2013', '2013'],
            '11.0'  => ['Microsoft Visual C++ 2012', '2012'],
            '10.0'  => ['Microsoft Visual C++ 2010', '2010'],
            '9.0'   => ['Microsoft Visual C++ 2008', '2008'],
            '8.0'   => ['Microsoft Visual C++ 2005', '2005'],
            '7.10'  => ['Microsoft Visual C++ 2003', '2003'],
            '7.0'   => ['Microsoft Visual C++ 2002', '2002'],
            '6.0'   => ['Microsoft Visual C++ 6.0', '6.0'],
            '2.25'  => ['Borland Delphi / C++ Builder', ''],
            '2.56'  => ['MinGW', ''],
        ];

        $key = "{$major}.{$minor}";
        if (isset($linkerMap[$key])) {
            $result->addDetection('compiler', $linkerMap[$key][0], $linkerMap[$key][1], 0.7, ['method' => 'linker_version']);
        }

        // MinGW / GCC heuristic: linker version 2.x with specific characteristics
        if ($major === 2 && $minor >= 20 && $minor <= 40) {
            if (strpos($data, 'GCC:') !== false || strpos($data, 'mingw') !== false) {
                $result->addDetection('compiler', 'MinGW/GCC', '', 0.85, ['method' => 'linker_version+string']);
            }
        }
    }

    /**
     * Analyze PE imports for additional detection clues.
     */
    private function analyzeImports(string $data, AnalysisResult $result, bool $is64, int $optOffset): void
    {
        // Import DLL name detection via string scanning
        $importDlls = [];

        $knownDlls = [
            'KERNEL32.dll', 'USER32.dll', 'ADVAPI32.dll', 'GDI32.dll',
            'SHELL32.dll', 'COMCTL32.dll', 'WSOCK32.dll', 'WS2_32.dll',
            'WININET.dll', 'CRYPT32.dll', 'WINTRUST.dll', 'NETAPI32.dll',
            'MSVCP140.dll', 'VCRUNTIME140.dll', 'ucrtbase.dll',
            'MSVCRT.dll', 'MSVCR100.dll', 'MSVCR110.dll', 'MSVCR120.dll',
            'python3.dll', 'python38.dll', 'python39.dll', 'python310.dll',
            'python311.dll', 'python312.dll',
            'lua51.dll', 'lua52.dll', 'lua53.dll', 'lua54.dll',
            'node.dll', 'libgcc_s_seh-1.dll', 'libstdc++-6.dll',
            'Qt5Core.dll', 'Qt6Core.dll', 'QtCore4.dll',
            'wxmsw30u_core_vc_custom.dll',
        ];

        foreach ($knownDlls as $dll) {
            if (stripos($data, $dll) !== false) {
                $importDlls[] = $dll;
            }
        }

        if (!empty($importDlls)) {
            $result->setMetadata('imported_dlls', $importDlls);
        }

        // CRT detection
        foreach ($importDlls as $dll) {
            $dllLower = strtolower($dll);
            if (strpos($dllLower, 'msvcp') !== false || strpos($dllLower, 'vcruntime') !== false) {
                $result->addDetection('library', 'Microsoft Visual C++ Runtime', '', 0.8, ['dll' => $dll]);
            }
            if (preg_match('/python\d+\.dll/i', $dll)) {
                $result->addDetection('library', 'Python Embedded', '', 0.8, ['dll' => $dll]);
            }
            if (preg_match('/qt[56]?core/i', $dll)) {
                $result->addDetection('framework', 'Qt Framework', '', 0.85, ['dll' => $dll]);
            }
        }
    }

    private function getMachineName(int $machine): string
    {
        $map = [
            self::IMAGE_FILE_MACHINE_I386 => 'i386 (x86)',
            self::IMAGE_FILE_MACHINE_AMD64 => 'AMD64 (x86-64)',
            self::IMAGE_FILE_MACHINE_ARM => 'ARM',
            self::IMAGE_FILE_MACHINE_ARM64 => 'ARM64 (AArch64)',
        ];
        return $map[$machine] ?? sprintf('Unknown (0x%04X)', $machine);
    }

    private function getSubsystemName(int $subsystem): string
    {
        $map = [
            self::IMAGE_SUBSYSTEM_NATIVE => 'Native',
            self::IMAGE_SUBSYSTEM_WINDOWS_GUI => 'Windows GUI',
            self::IMAGE_SUBSYSTEM_WINDOWS_CUI => 'Windows Console',
            self::IMAGE_SUBSYSTEM_EFI_APPLICATION => 'EFI Application',
            self::IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => 'Windows Boot',
        ];
        return $map[$subsystem] ?? sprintf('Unknown (%d)', $subsystem);
    }

    private function getRichToolName(int $toolId): string
    {
        // Common Rich header tool IDs
        $map = [
            0x01 => 'Import',
            0x04 => 'Linker',
            0x06 => 'CVTRES',
            0x0A => 'C Compiler',
            0x0B => 'C++ Compiler',
            0x0E => 'ASM (MASM)',
            0x5D => 'C Compiler',
            0x5E => 'C++ Compiler',
            0x60 => 'Linker',
            0x93 => 'C Compiler',
            0x94 => 'C++ Compiler',
            0xFF => 'Linker',
            0x100 => 'Export',
            0x103 => 'C Compiler',
            0x104 => 'C++ Compiler',
            0x105 => 'ASM (MASM)',
            0x106 => 'Linker/CVTRES',
        ];
        return $map[$toolId] ?? sprintf('Tool(0x%02X)', $toolId);
    }

    private function inferMSVCVersion(array $entries, AnalysisResult $result): void
    {
        // Map build IDs to MSVC versions
        $buildVersions = [
            [30729, 'MSVC 2008 SP1'],
            [40219, 'MSVC 2010 SP1'],
            [50727, 'MSVC 2005'],
            [21022, 'MSVC 2008'],
        ];

        foreach ($entries as $entry) {
            $buildId = $entry['build_id'];
            foreach ($buildVersions as [$id, $version]) {
                if ($buildId === $id) {
                    $result->addDetection('compiler', $version, '', 0.8, ['method' => 'rich_header']);
                    return;
                }
            }
            // VS 2015-2022 range: build IDs 23026-34000+
            if ($buildId >= 23026 && $buildId < 30000) {
                $result->addDetection('compiler', 'Microsoft Visual C++', '2015+', 0.7, ['method' => 'rich_header']);
                return;
            }
        }
    }
}
