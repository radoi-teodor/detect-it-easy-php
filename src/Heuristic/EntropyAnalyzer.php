<?php

declare(strict_types=1);

namespace DetectItEasy\Heuristic;

/**
 * Analyzes Shannon entropy of binary data.
 *
 * High entropy (>7.0) suggests compression, encryption, or packing.
 * Low entropy (<1.0) suggests sparse or uniform data.
 */
class EntropyAnalyzer
{
    /** @var int Block size for sectional entropy analysis */
    private $blockSize;

    /**
     * @param int $blockSize Size of blocks for sectional analysis (default 256 bytes).
     */
    public function __construct(int $blockSize = 256)
    {
        $this->blockSize = $blockSize;
    }

    /**
     * Compute entropy analysis for given data.
     *
     * @param string $data
     * @return array{overall: float, min: float, max: float, blocks: array<int, float>, assessment: string}
     */
    public function analyze(string $data): array
    {
        $len = strlen($data);
        if ($len === 0) {
            return [
                'overall' => 0.0,
                'min' => 0.0,
                'max' => 0.0,
                'blocks' => [],
                'assessment' => 'empty',
            ];
        }

        $overall = $this->shannonEntropy($data);

        // Block-level analysis (limit to first 64 blocks to keep it fast)
        $blocks = [];
        $min = 8.0;
        $max = 0.0;
        $maxBlocks = min((int) ceil($len / $this->blockSize), 64);

        for ($i = 0; $i < $maxBlocks; $i++) {
            $blockData = substr($data, $i * $this->blockSize, $this->blockSize);
            $e = $this->shannonEntropy($blockData);
            $blocks[] = round($e, 4);
            if ($e < $min) {
                $min = $e;
            }
            if ($e > $max) {
                $max = $e;
            }
        }

        if (empty($blocks)) {
            $min = $overall;
            $max = $overall;
        }

        return [
            'overall' => round($overall, 4),
            'min' => round($min, 4),
            'max' => round($max, 4),
            'blocks' => $blocks,
            'assessment' => $this->assess($overall),
        ];
    }

    /**
     * Calculate Shannon entropy of a byte string.
     * Returns value between 0.0 (uniform) and 8.0 (maximum randomness).
     */
    public function shannonEntropy(string $data): float
    {
        $len = strlen($data);
        if ($len === 0) {
            return 0.0;
        }

        // Count byte frequencies
        $freq = array_fill(0, 256, 0);
        for ($i = 0; $i < $len; $i++) {
            $freq[ord($data[$i])]++;
        }

        $entropy = 0.0;
        foreach ($freq as $count) {
            if ($count === 0) {
                continue;
            }
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    /**
     * Provide a human-readable assessment of entropy.
     */
    private function assess(float $entropy): string
    {
        if ($entropy < 1.0) {
            return 'very_low';
        }
        if ($entropy < 3.0) {
            return 'low';
        }
        if ($entropy < 5.0) {
            return 'moderate';
        }
        if ($entropy < 6.5) {
            return 'normal';
        }
        if ($entropy < 7.2) {
            return 'high';
        }
        if ($entropy < 7.8) {
            return 'very_high_likely_packed';
        }
        return 'extremely_high_likely_encrypted';
    }
}
