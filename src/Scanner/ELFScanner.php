<?php

declare(strict_types=1);

namespace DetectItEasy\Scanner;

use DetectItEasy\Result\AnalysisResult;

/**
 * Deep scanner for ELF (Executable and Linkable Format) files.
 */
class ELFScanner extends AbstractScanner
{
    // ELF constants
    private const ELFCLASS32 = 1;
    private const ELFCLASS64 = 2;

    private const ELFDATA2LSB = 1; // Little-endian
    private const ELFDATA2MSB = 2; // Big-endian

    private const ET_NONE = 0;
    private const ET_REL  = 1;
    private const ET_EXEC = 2;
    private const ET_DYN  = 3;
    private const ET_CORE = 4;

    public function deepScan(string $data, int $fileSize, AnalysisResult $result): void
    {
        if (strlen($data) < 52) {
            return;
        }

        // ELF header
        $eiClass = ord($data[4]);
        $eiData = ord($data[5]);
        $eiOsAbi = ord($data[7]);

        $is64 = ($eiClass === self::ELFCLASS64);
        $isLE = ($eiData === self::ELFDATA2LSB);

        if ($is64) {
            $result->setFileFormat([
                'format' => 'ELF64',
                'description' => 'ELF Executable (64-bit)',
                'mime_type' => 'application/x-elf',
            ]);
        }

        $result->setMetadata('elf_class', $is64 ? '64-bit' : '32-bit');
        $result->setMetadata('endianness', $isLE ? 'little-endian' : 'big-endian');
        $result->setMetadata('os_abi', $this->getOsAbiName($eiOsAbi));

        // Parse type and machine using appropriate endianness
        if ($isLE) {
            $type = $this->readUint16LE($data, 16);
            $machine = $this->readUint16LE($data, 18);
        } else {
            $type = (ord($data[16]) << 8) | ord($data[17]);
            $machine = (ord($data[18]) << 8) | ord($data[19]);
        }

        $result->setMetadata('elf_type', $this->getTypeName($type));
        $result->setMetadata('machine', $this->getMachineName($machine));

        // Entry point
        if ($is64) {
            // 64-bit entry point at offset 24, 8 bytes
            if (strlen($data) >= 32) {
                $ep = $isLE
                    ? $this->readUint64LE($data, 24)
                    : $this->readUint32BE($data, 24); // Simplified for big-endian
                $result->setMetadata('entry_point', sprintf('0x%X', $ep));
            }
        } else {
            if (strlen($data) >= 28) {
                $ep = $isLE
                    ? $this->readUint32LE($data, 24)
                    : $this->readUint32BE($data, 24);
                $result->setMetadata('entry_point', sprintf('0x%08X', $ep));
            }
        }

        // Section header info
        if ($is64 && strlen($data) >= 64) {
            $shoff = $isLE ? $this->readUint64LE($data, 40) : 0;
            $shentsize = $isLE ? $this->readUint16LE($data, 58) : 0;
            $shnum = $isLE ? $this->readUint16LE($data, 60) : 0;
            $result->setMetadata('sections_count', $shnum);
        } elseif (!$is64 && strlen($data) >= 52) {
            $shoff = $isLE ? $this->readUint32LE($data, 32) : $this->readUint32BE($data, 32);
            $shentsize = $isLE ? $this->readUint16LE($data, 46) : 0;
            $shnum = $isLE ? $this->readUint16LE($data, 48) : 0;
            $result->setMetadata('sections_count', $shnum);
        }

        // Parse section names for detection
        $sectionNames = $this->extractSectionNames($data, $is64, $isLE);
        if (!empty($sectionNames)) {
            $result->setMetadata('section_names', $sectionNames);
        }

        // Detect compiler, packer, etc.
        $this->detectFromSignatures($data, $result);
        $this->heuristicDetection($data, $result, $sectionNames);
    }

    /**
     * Extract section names from the ELF section header table.
     *
     * @return string[]
     */
    private function extractSectionNames(string $data, bool $is64, bool $isLE): array
    {
        $dataLen = strlen($data);

        if ($is64) {
            if ($dataLen < 64) {
                return [];
            }
            $shoff = $isLE ? $this->readUint64LE($data, 40) : 0;
            $shentsize = $isLE ? $this->readUint16LE($data, 58) : 0;
            $shnum = $isLE ? $this->readUint16LE($data, 60) : 0;
            $shstrndx = $isLE ? $this->readUint16LE($data, 62) : 0;
        } else {
            if ($dataLen < 52) {
                return [];
            }
            $shoff = $isLE ? $this->readUint32LE($data, 32) : $this->readUint32BE($data, 32);
            $shentsize = $isLE ? $this->readUint16LE($data, 46) : 0;
            $shnum = $isLE ? $this->readUint16LE($data, 48) : 0;
            $shstrndx = $isLE ? $this->readUint16LE($data, 50) : 0;
        }

        if ($shoff === 0 || $shentsize === 0 || $shnum === 0 || $shstrndx >= $shnum) {
            return [];
        }

        // Get the section header string table
        $strTabHeaderOffset = (int)$shoff + ($shstrndx * $shentsize);

        if ($is64) {
            if ($strTabHeaderOffset + 64 > $dataLen) {
                return [];
            }
            $strTabOffset = $isLE ? $this->readUint64LE($data, $strTabHeaderOffset + 24) : 0;
            $strTabSize = $isLE ? $this->readUint64LE($data, $strTabHeaderOffset + 32) : 0;
        } else {
            if ($strTabHeaderOffset + 40 > $dataLen) {
                return [];
            }
            $strTabOffset = $isLE ? $this->readUint32LE($data, $strTabHeaderOffset + 16) : 0;
            $strTabSize = $isLE ? $this->readUint32LE($data, $strTabHeaderOffset + 20) : 0;
        }

        if ($strTabOffset === 0 || (int)$strTabOffset + (int)$strTabSize > $dataLen) {
            return [];
        }

        $names = [];
        $limit = min($shnum, 64);
        for ($i = 0; $i < $limit; $i++) {
            $headerOffset = (int)$shoff + ($i * $shentsize);
            if ($headerOffset + 4 > $dataLen) {
                break;
            }
            $nameIdx = $isLE ? $this->readUint32LE($data, $headerOffset) : $this->readUint32BE($data, $headerOffset);
            if ($nameIdx < $strTabSize) {
                $name = $this->readString($data, (int)$strTabOffset + $nameIdx, 64);
                if ($name !== '') {
                    $names[] = $name;
                }
            }
        }

        return $names;
    }

    private function detectFromSignatures(string $data, AnalysisResult $result): void
    {
        $categories = ['compilers', 'packers', 'protectors'];

        foreach ($categories as $category) {
            $signatures = $this->signatureDb->getSignatures('elf', $category);
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
     * @param string[] $sectionNames
     */
    private function heuristicDetection(string $data, AnalysisResult $result, array $sectionNames): void
    {
        // GCC detection
        if (preg_match('/GCC:\s*\(.*?\)\s*([\d.]+)/', $data, $m)) {
            $result->addDetection('compiler', 'GCC', $m[1], 0.95, ['method' => 'comment_string']);
        } elseif (strpos($data, 'GCC:') !== false) {
            $result->addDetection('compiler', 'GCC', '', 0.85, ['method' => 'comment_string']);
        }

        // Clang/LLVM
        if (preg_match('/clang version ([\d.]+)/', $data, $m)) {
            $result->addDetection('compiler', 'Clang/LLVM', $m[1], 0.95, ['method' => 'comment_string']);
        }

        // Go
        if (strpos($data, 'Go build ID:') !== false || strpos($data, 'runtime.main') !== false) {
            $result->addDetection('compiler', 'Go (Golang)', '', 0.9, ['method' => 'string_match']);
            // Detect Go version
            if (preg_match('/go(1\.\d+(?:\.\d+)?)/', $data, $m)) {
                $result->addDetection('compiler', 'Go', $m[1], 0.9, ['method' => 'version_string']);
            }
        }

        // Rust
        if (strpos($data, '/rustc/') !== false || strpos($data, 'rust_begin_unwind') !== false) {
            $result->addDetection('compiler', 'Rust (rustc)', '', 0.85, ['method' => 'string_match']);
        }

        // UPX
        if (strpos($data, 'UPX!') !== false || strpos($data, "\$Info: This file is packed with the UPX") !== false) {
            $result->addDetection('packer', 'UPX', '', 0.95, ['method' => 'string_match']);
        }

        // Stripped binary detection
        if (in_array('.symtab', $sectionNames) === false && in_array('.strtab', $sectionNames) === false) {
            $result->setMetadata('stripped', true);
        } else {
            $result->setMetadata('stripped', false);
        }

        // Static vs dynamic
        if (in_array('.dynamic', $sectionNames) || in_array('.dynsym', $sectionNames)) {
            $result->setMetadata('linking', 'dynamic');
        } else {
            $result->setMetadata('linking', 'static');
        }

        // Debug info
        if (in_array('.debug_info', $sectionNames) || in_array('.debug_abbrev', $sectionNames)) {
            $result->setMetadata('debug_info', true);
        }

        // Android specific
        if (strpos($data, 'libandroid') !== false || strpos($data, 'JNI_OnLoad') !== false) {
            $result->setMetadata('android_native', true);
        }
    }

    private function getOsAbiName(int $abi): string
    {
        $map = [
            0x00 => 'UNIX System V',
            0x01 => 'HP-UX',
            0x02 => 'NetBSD',
            0x03 => 'Linux',
            0x04 => 'GNU Hurd',
            0x06 => 'Solaris',
            0x07 => 'AIX',
            0x08 => 'IRIX',
            0x09 => 'FreeBSD',
            0x0C => 'OpenBSD',
            0x61 => 'ARM EABI',
            0x97 => 'ARM',
        ];
        return $map[$abi] ?? sprintf('Unknown (0x%02X)', $abi);
    }

    private function getTypeName(int $type): string
    {
        $map = [
            self::ET_NONE => 'None',
            self::ET_REL => 'Relocatable',
            self::ET_EXEC => 'Executable',
            self::ET_DYN => 'Shared Object / PIE',
            self::ET_CORE => 'Core Dump',
        ];
        return $map[$type] ?? sprintf('Unknown (%d)', $type);
    }

    private function getMachineName(int $machine): string
    {
        $map = [
            0x02 => 'SPARC',
            0x03 => 'x86 (i386)',
            0x08 => 'MIPS',
            0x14 => 'PowerPC',
            0x15 => 'PowerPC64',
            0x16 => 'S390',
            0x28 => 'ARM',
            0x2A => 'SuperH',
            0x32 => 'IA-64',
            0x3E => 'x86-64 (AMD64)',
            0xB7 => 'AArch64 (ARM64)',
            0xF3 => 'RISC-V',
            0xF7 => 'BPF',
        ];
        return $map[$machine] ?? sprintf('Unknown (0x%02X)', $machine);
    }
}
