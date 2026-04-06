<?php

declare(strict_types=1);

namespace DetectItEasy\Scanner;

use DetectItEasy\Result\AnalysisResult;

/**
 * Deep scanner for Mach-O (macOS/iOS) executables.
 */
class MachOScanner extends AbstractScanner
{
    // Mach-O constants
    private const MH_MAGIC    = 0xFEEDFACE;
    private const MH_CIGAM    = 0xCEFAEDFE;
    private const MH_MAGIC_64 = 0xFEEDFACF;
    private const MH_CIGAM_64 = 0xCFFAEDFE;
    private const FAT_MAGIC   = 0xCAFEBABE;

    // File types
    private const MH_EXECUTE  = 0x2;
    private const MH_DYLIB    = 0x6;
    private const MH_DYLINKER = 0x7;
    private const MH_BUNDLE   = 0x8;
    private const MH_DSYM     = 0xA;
    private const MH_KEXT_BUNDLE = 0xB;

    // Load commands
    private const LC_SEGMENT       = 0x1;
    private const LC_SEGMENT_64    = 0x19;
    private const LC_UUID          = 0x1B;
    private const LC_VERSION_MIN_MACOSX  = 0x24;
    private const LC_VERSION_MIN_IPHONEOS = 0x25;
    private const LC_BUILD_VERSION = 0x32;
    private const LC_SOURCE_VERSION = 0x2A;

    public function deepScan(string $data, int $fileSize, AnalysisResult $result): void
    {
        if (strlen($data) < 28) {
            return;
        }

        $magic = $this->readUint32BE($data, 0);

        // Handle fat (universal) binary
        if ($magic === self::FAT_MAGIC) {
            $this->scanFatBinary($data, $fileSize, $result);
            return;
        }

        // Determine endianness and bitness
        $isLE = ($magic === self::MH_CIGAM || $magic === self::MH_CIGAM_64);
        $is64 = ($magic === self::MH_MAGIC_64 || $magic === self::MH_CIGAM_64);

        $readU32 = $isLE
            ? function (string $d, int $o) { return $this->readUint32LE($d, $o); }
            : function (string $d, int $o) { return $this->readUint32BE($d, $o); };

        // Mach header
        $cpuType = $readU32($data, 4);
        $cpuSubtype = $readU32($data, 8);
        $fileType = $readU32($data, 12);
        $ncmds = $readU32($data, 16);
        $sizeofcmds = $readU32($data, 20);
        $flags = $readU32($data, 24);

        $result->setMetadata('cpu_type', $this->getCpuTypeName($cpuType));
        $result->setMetadata('file_type', $this->getFileTypeName($fileType));
        $result->setMetadata('is_64bit', $is64);
        $result->setMetadata('load_commands_count', $ncmds);

        // Parse load commands
        $headerSize = $is64 ? 32 : 28;
        $offset = $headerSize;
        $segments = [];
        $uuid = null;
        $minVersion = null;
        $platform = null;

        for ($i = 0; $i < $ncmds && $offset + 8 <= strlen($data); $i++) {
            $cmd = $readU32($data, $offset);
            $cmdsize = $readU32($data, $offset + 4);

            if ($cmdsize < 8 || $offset + $cmdsize > strlen($data)) {
                break;
            }

            switch ($cmd) {
                case self::LC_SEGMENT:
                case self::LC_SEGMENT_64:
                    $segname = $this->readString($data, $offset + 8, 16);
                    $segments[] = $segname;
                    break;

                case self::LC_UUID:
                    if ($offset + 24 <= strlen($data)) {
                        $uuidBytes = substr($data, $offset + 8, 16);
                        $uuid = strtoupper(bin2hex($uuidBytes));
                        $uuid = substr($uuid, 0, 8) . '-' . substr($uuid, 8, 4) . '-' .
                                substr($uuid, 12, 4) . '-' . substr($uuid, 16, 4) . '-' .
                                substr($uuid, 20, 12);
                    }
                    break;

                case self::LC_BUILD_VERSION:
                    if ($offset + 16 <= strlen($data)) {
                        $platformId = $readU32($data, $offset + 8);
                        $minos = $readU32($data, $offset + 12);
                        $platform = $this->getPlatformName($platformId);
                        $minVersion = $this->decodeVersion($minos);
                    }
                    break;

                case self::LC_VERSION_MIN_MACOSX:
                    if ($offset + 12 <= strlen($data)) {
                        $platform = 'macOS';
                        $minVersion = $this->decodeVersion($readU32($data, $offset + 8));
                    }
                    break;

                case self::LC_VERSION_MIN_IPHONEOS:
                    if ($offset + 12 <= strlen($data)) {
                        $platform = 'iOS';
                        $minVersion = $this->decodeVersion($readU32($data, $offset + 8));
                    }
                    break;
            }

            $offset += $cmdsize;
        }

        if (!empty($segments)) {
            $result->setMetadata('segments', $segments);
        }
        if ($uuid !== null) {
            $result->setMetadata('uuid', $uuid);
        }
        if ($platform !== null) {
            $result->setMetadata('platform', $platform);
        }
        if ($minVersion !== null) {
            $result->setMetadata('min_os_version', $minVersion);
        }

        // Heuristic detections
        $this->heuristicDetection($data, $result, $segments);

        // Signature-based detection
        $this->detectFromSignatures($data, $result);
    }

    private function scanFatBinary(string $data, int $fileSize, AnalysisResult $result): void
    {
        if (strlen($data) < 8) {
            return;
        }

        $nfatArch = $this->readUint32BE($data, 4);
        $result->setMetadata('fat_architectures', $nfatArch);

        $archs = [];
        $offset = 8;
        for ($i = 0; $i < $nfatArch && $offset + 20 <= strlen($data); $i++) {
            $cpuType = $this->readUint32BE($data, $offset);
            $cpuSubtype = $this->readUint32BE($data, $offset + 4);
            $archOffset = $this->readUint32BE($data, $offset + 8);
            $archSize = $this->readUint32BE($data, $offset + 12);

            $archs[] = [
                'cpu_type' => $this->getCpuTypeName($cpuType),
                'offset' => $archOffset,
                'size' => $archSize,
            ];

            $offset += 20;
        }

        $result->setMetadata('architectures', $archs);

        // Analyze the first architecture slice
        if (!empty($archs) && $archs[0]['offset'] + 28 <= strlen($data)) {
            $sliceData = substr($data, $archs[0]['offset'], min($archs[0]['size'], strlen($data) - $archs[0]['offset']));
            if (strlen($sliceData) >= 28) {
                $this->heuristicDetection($sliceData, $result, []);
                $this->detectFromSignatures($sliceData, $result);
            }
        }
    }

    private function heuristicDetection(string $data, AnalysisResult $result, array $segments): void
    {
        // Swift detection
        if (strpos($data, 'swift') !== false && (strpos($data, 'libswiftCore') !== false || strpos($data, '__swift5') !== false)) {
            $result->addDetection('compiler', 'Apple Swift', '', 0.9, ['method' => 'string_match']);
        }

        // Objective-C detection
        if (in_array('__OBJC', $segments) || strpos($data, 'objc_msgSend') !== false) {
            $result->addDetection('compiler', 'Objective-C', '', 0.85, ['method' => 'segment_analysis']);
        }

        // Clang/LLVM
        if (preg_match('/Apple (?:clang|LLVM) version ([\d.]+)/', $data, $m)) {
            $result->addDetection('compiler', 'Apple Clang/LLVM', $m[1], 0.95, ['method' => 'comment_string']);
        } elseif (preg_match('/clang[- ]version ([\d.]+)/', $data, $m)) {
            $result->addDetection('compiler', 'Clang/LLVM', $m[1], 0.9, ['method' => 'comment_string']);
        }

        // Go
        if (strpos($data, 'Go build ID:') !== false || strpos($data, 'runtime.main') !== false) {
            $result->addDetection('compiler', 'Go (Golang)', '', 0.9, ['method' => 'string_match']);
        }

        // Rust
        if (strpos($data, '/rustc/') !== false) {
            $result->addDetection('compiler', 'Rust', '', 0.85, ['method' => 'string_match']);
        }

        // UPX
        if (strpos($data, 'UPX!') !== false) {
            $result->addDetection('packer', 'UPX', '', 0.95, ['method' => 'string_match']);
        }

        // Code signing
        if (strpos($data, 'Apple Code Signing') !== false || in_array('__LINKEDIT', $segments)) {
            $result->setMetadata('code_signed', true);
        }

        // Check for common frameworks
        if (strpos($data, 'UIKit') !== false) {
            $result->addDetection('framework', 'UIKit (iOS)', '', 0.8, ['method' => 'string_match']);
        }
        if (strpos($data, 'AppKit') !== false) {
            $result->addDetection('framework', 'AppKit (macOS)', '', 0.8, ['method' => 'string_match']);
        }
        if (strpos($data, 'Electron') !== false && strpos($data, 'node') !== false) {
            $result->addDetection('framework', 'Electron', '', 0.75, ['method' => 'string_match']);
        }
    }

    private function detectFromSignatures(string $data, AnalysisResult $result): void
    {
        $categories = ['compilers', 'packers'];

        foreach ($categories as $category) {
            $signatures = $this->signatureDb->getSignatures('macho', $category);
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

    private function getCpuTypeName(int $cpuType): string
    {
        // Handle CPU_ARCH_ABI64 flag (0x01000000)
        $base = $cpuType & 0x00FFFFFF;
        $is64 = ($cpuType & 0x01000000) !== 0;

        $map = [
            1 => 'VAX',
            6 => 'MC680x0',
            7 => 'x86',
            10 => 'MC98000',
            11 => 'HPPA',
            12 => 'ARM',
            13 => 'MC88000',
            14 => 'SPARC',
            15 => 'i860',
            18 => 'PowerPC',
        ];

        $name = $map[$base] ?? sprintf('Unknown(%d)', $base);
        if ($is64) {
            if ($base === 7) {
                return 'x86_64';
            }
            if ($base === 12) {
                return 'ARM64';
            }
            if ($base === 18) {
                return 'PowerPC64';
            }
            return $name . '_64';
        }
        return $name;
    }

    private function getFileTypeName(int $type): string
    {
        $map = [
            0x1 => 'Object',
            self::MH_EXECUTE => 'Executable',
            0x3 => 'Fixed VM Shared Library',
            0x4 => 'Core',
            0x5 => 'Preloaded Executable',
            self::MH_DYLIB => 'Dynamic Library',
            self::MH_DYLINKER => 'Dynamic Linker',
            self::MH_BUNDLE => 'Bundle',
            0x9 => 'Dynamic Library Stub',
            self::MH_DSYM => 'Debug Symbols (dSYM)',
            self::MH_KEXT_BUNDLE => 'Kernel Extension',
        ];
        return $map[$type] ?? sprintf('Unknown (%d)', $type);
    }

    private function getPlatformName(int $platform): string
    {
        $map = [
            1 => 'macOS',
            2 => 'iOS',
            3 => 'tvOS',
            4 => 'watchOS',
            5 => 'bridgeOS',
            6 => 'Mac Catalyst',
            7 => 'iOS Simulator',
            8 => 'tvOS Simulator',
            9 => 'watchOS Simulator',
            10 => 'DriverKit',
            11 => 'visionOS',
            12 => 'visionOS Simulator',
        ];
        return $map[$platform] ?? sprintf('Unknown (%d)', $platform);
    }

    private function decodeVersion(int $version): string
    {
        $major = ($version >> 16) & 0xFFFF;
        $minor = ($version >> 8) & 0xFF;
        $patch = $version & 0xFF;
        return "{$major}.{$minor}.{$patch}";
    }
}
