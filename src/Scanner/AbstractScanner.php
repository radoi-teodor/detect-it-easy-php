<?php

declare(strict_types=1);

namespace DetectItEasy\Scanner;

use DetectItEasy\Signature\SignatureDatabase;

abstract class AbstractScanner implements ScannerInterface
{
    /** @var SignatureDatabase */
    protected $signatureDb;

    public function __construct(SignatureDatabase $signatureDb)
    {
        $this->signatureDb = $signatureDb;
    }

    /**
     * Read a little-endian unsigned 16-bit integer.
     */
    protected function readUint16LE(string $data, int $offset): int
    {
        if ($offset + 2 > strlen($data)) {
            return 0;
        }
        $val = unpack('v', substr($data, $offset, 2));
        return $val ? $val[1] : 0;
    }

    /**
     * Read a little-endian unsigned 32-bit integer.
     */
    protected function readUint32LE(string $data, int $offset): int
    {
        if ($offset + 4 > strlen($data)) {
            return 0;
        }
        $val = unpack('V', substr($data, $offset, 4));
        return $val ? $val[1] : 0;
    }

    /**
     * Read a big-endian unsigned 32-bit integer.
     */
    protected function readUint32BE(string $data, int $offset): int
    {
        if ($offset + 4 > strlen($data)) {
            return 0;
        }
        $val = unpack('N', substr($data, $offset, 4));
        return $val ? $val[1] : 0;
    }

    /**
     * Read a little-endian unsigned 64-bit integer (as float on 32-bit PHP).
     *
     * @return int|float
     */
    protected function readUint64LE(string $data, int $offset)
    {
        if ($offset + 8 > strlen($data)) {
            return 0;
        }
        $val = unpack('P', substr($data, $offset, 8));
        return $val ? $val[1] : 0;
    }

    /**
     * Read a null-terminated ASCII string.
     */
    protected function readString(string $data, int $offset, int $maxLen = 256): string
    {
        if ($offset >= strlen($data)) {
            return '';
        }
        $end = min($offset + $maxLen, strlen($data));
        $str = '';
        for ($i = $offset; $i < $end; $i++) {
            $ch = $data[$i];
            if ($ch === "\0") {
                break;
            }
            $str .= $ch;
        }
        return $str;
    }

    /**
     * Search for a byte pattern in data.
     *
     * @param string $data
     * @param string $pattern Raw bytes to search for.
     * @param int $start
     * @param int|null $length
     * @return int|false Offset or false.
     */
    protected function findPattern(string $data, string $pattern, int $start = 0, ?int $length = null)
    {
        $haystack = $length !== null ? substr($data, $start, $length) : substr($data, $start);
        $pos = strpos($haystack, $pattern);
        if ($pos === false) {
            return false;
        }
        return $start + $pos;
    }

    /**
     * Match a signature pattern with wildcards.
     * Pattern format: "4D 5A ?? ?? 50 45" where ?? is a wildcard byte.
     *
     * @param string $data
     * @param string $hexPattern Space-separated hex bytes, ?? for wildcard.
     * @param int $offset Offset in $data to start matching.
     * @return bool
     */
    protected function matchHexPattern(string $data, string $hexPattern, int $offset = 0): bool
    {
        $parts = explode(' ', trim($hexPattern));
        $len = count($parts);

        if ($offset + $len > strlen($data)) {
            return false;
        }

        for ($i = 0; $i < $len; $i++) {
            if ($parts[$i] === '??' || $parts[$i] === '?') {
                continue;
            }
            $expected = (int) hexdec($parts[$i]);
            $actual = ord($data[$offset + $i]);
            if ($expected !== $actual) {
                return false;
            }
        }

        return true;
    }

    /**
     * Scan data against a set of signature definitions.
     *
     * @param string $data Binary data.
     * @param array<int, array<string, mixed>> $signatures Signature definitions.
     * @return array<int, array{name: string, version: string, confidence: float, category: string}>
     */
    protected function matchSignatures(string $data, array $signatures): array
    {
        $matches = [];

        foreach ($signatures as $sig) {
            $matched = false;
            $confidence = (float) ($sig['confidence'] ?? 0.9);

            if (isset($sig['hex_patterns'])) {
                foreach ($sig['hex_patterns'] as $pattern) {
                    $patOffset = $pattern['offset'] ?? 0;
                    if ($this->matchHexPattern($data, $pattern['bytes'], $patOffset)) {
                        $matched = true;
                        break;
                    }
                }
            }

            if (!$matched && isset($sig['strings'])) {
                foreach ($sig['strings'] as $search) {
                    $searchOffset = $search['offset'] ?? null;
                    $searchStr = $search['value'];
                    if ($searchOffset !== null) {
                        if ($this->findPattern($data, $searchStr, $searchOffset, strlen($searchStr) + 16) !== false) {
                            $matched = true;
                            break;
                        }
                    } else {
                        if (strpos($data, $searchStr) !== false) {
                            $matched = true;
                            break;
                        }
                    }
                }
            }

            if ($matched) {
                $matches[] = [
                    'name' => $sig['name'],
                    'version' => $sig['version'] ?? '',
                    'confidence' => $confidence,
                    'category' => $sig['category'] ?? 'unknown',
                ];
            }
        }

        return $matches;
    }
}
