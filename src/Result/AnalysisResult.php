<?php

declare(strict_types=1);

namespace DetectItEasy\Result;

/**
 * Represents the results of a file analysis.
 */
class AnalysisResult
{
    /** @var string */
    private $filePath;

    /** @var int */
    private $fileSize;

    /** @var string|null */
    private $fileFormat;

    /** @var string|null */
    private $formatDescription;

    /** @var string|null */
    private $mimeType;

    /** @var array<string, mixed> */
    private $detections = [];

    /** @var array<string, mixed> */
    private $entropy = [];

    /** @var array<string, mixed> */
    private $metadata = [];

    /** @var string|null */
    private $error;

    public function __construct(string $filePath, int $fileSize)
    {
        $this->filePath = $filePath;
        $this->fileSize = $fileSize;
    }

    public function getFilePath(): string
    {
        return $this->filePath;
    }

    public function getFileSize(): int
    {
        return $this->fileSize;
    }

    public function getFileFormat(): ?string
    {
        return $this->fileFormat;
    }

    /**
     * @param array{format: string, description: string, mime_type: string}|null $detection
     */
    public function setFileFormat(?array $detection): void
    {
        if ($detection !== null) {
            $this->fileFormat = $detection['format'] ?? null;
            $this->formatDescription = $detection['description'] ?? null;
            $this->mimeType = $detection['mime_type'] ?? null;
        }
    }

    public function getFormatDescription(): ?string
    {
        return $this->formatDescription;
    }

    public function getMimeType(): ?string
    {
        return $this->mimeType;
    }

    /**
     * Add a detection finding (compiler, packer, protector, linker, etc.).
     *
     * @param string $category  e.g. 'compiler', 'packer', 'protector', 'linker', 'library', 'installer'
     * @param string $name      e.g. 'UPX', 'Microsoft Visual C++'
     * @param string $version   e.g. '3.96', '2019'
     * @param float  $confidence 0.0 to 1.0
     * @param array<string, mixed> $extra Additional detection metadata
     */
    public function addDetection(
        string $category,
        string $name,
        string $version = '',
        float $confidence = 1.0,
        array $extra = []
    ): void {
        if (!isset($this->detections[$category])) {
            $this->detections[$category] = [];
        }

        // Deduplicate: if same category+name exists, keep the higher confidence one
        foreach ($this->detections[$category] as $i => $existing) {
            if ($existing['name'] === $name) {
                if ($confidence > $existing['confidence']) {
                    $this->detections[$category][$i] = [
                        'name' => $name,
                        'version' => $version !== '' ? $version : $existing['version'],
                        'confidence' => $confidence,
                        'extra' => $extra,
                    ];
                } elseif ($version !== '' && $existing['version'] === '') {
                    $this->detections[$category][$i]['version'] = $version;
                }
                return;
            }
        }

        $this->detections[$category][] = [
            'name' => $name,
            'version' => $version,
            'confidence' => $confidence,
            'extra' => $extra,
        ];
    }

    /**
     * @return array<string, array<int, array{name: string, version: string, confidence: float, extra: array}>>
     */
    public function getDetections(): array
    {
        return $this->detections;
    }

    /**
     * Get detections for a specific category.
     *
     * @param string $category
     * @return array<int, array{name: string, version: string, confidence: float, extra: array}>
     */
    public function getDetectionsByCategory(string $category): array
    {
        return $this->detections[$category] ?? [];
    }

    /**
     * Check if the file appears to be packed.
     */
    public function isPacked(): bool
    {
        if (!empty($this->detections['packer']) || !empty($this->detections['protector'])) {
            return true;
        }

        // High entropy suggests packing/encryption, but only for executable formats
        $executableFormats = ['PE', 'PE64', 'ELF', 'ELF64', 'Mach-O', 'Mach-O 64', 'Mach-O Universal', 'DEX', 'MS-DOS'];
        if (isset($this->entropy['overall']) && $this->entropy['overall'] > 7.2
            && in_array($this->fileFormat, $executableFormats, true)) {
            return true;
        }

        return false;
    }

    /**
     * @param array<string, mixed> $entropy
     */
    public function setEntropy(array $entropy): void
    {
        $this->entropy = $entropy;
    }

    /**
     * @return array<string, mixed>
     */
    public function getEntropy(): array
    {
        return $this->entropy;
    }

    /**
     * @param string $key
     * @param mixed $value
     */
    public function setMetadata(string $key, $value): void
    {
        $this->metadata[$key] = $value;
    }

    /**
     * @param string|null $key
     * @return mixed
     */
    public function getMetadata(?string $key = null)
    {
        if ($key === null) {
            return $this->metadata;
        }
        return $this->metadata[$key] ?? null;
    }

    public function setError(string $error): void
    {
        $this->error = $error;
    }

    public function getError(): ?string
    {
        return $this->error;
    }

    public function hasError(): bool
    {
        return $this->error !== null;
    }

    /**
     * Convert to a structured array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $data = [
            'file' => $this->filePath,
            'size' => $this->fileSize,
            'format' => $this->fileFormat,
            'description' => $this->formatDescription,
            'mime_type' => $this->mimeType,
            'packed' => $this->isPacked(),
        ];

        if (!empty($this->detections)) {
            $data['detections'] = $this->detections;
        }

        if (!empty($this->entropy)) {
            $data['entropy'] = $this->entropy;
        }

        if (!empty($this->metadata)) {
            $data['metadata'] = $this->metadata;
        }

        if ($this->error !== null) {
            $data['error'] = $this->error;
        }

        return $data;
    }

    /**
     * Get a human-readable summary.
     */
    public function getSummary(): string
    {
        if ($this->error !== null) {
            return "Error: {$this->error}";
        }

        $lines = [];
        $lines[] = "File: {$this->filePath}";
        $lines[] = "Size: " . $this->formatSize($this->fileSize);
        $lines[] = "Format: " . ($this->formatDescription ?? 'Unknown');

        if (!empty($this->detections)) {
            foreach ($this->detections as $category => $items) {
                foreach ($items as $item) {
                    $entry = ucfirst($category) . ': ' . $item['name'];
                    if ($item['version'] !== '') {
                        $entry .= ' ' . $item['version'];
                    }
                    $pct = (int) round($item['confidence'] * 100);
                    $entry .= " ({$pct}%)";
                    $lines[] = $entry;
                }
            }
        }

        if ($this->isPacked()) {
            $lines[] = "** File appears to be packed/protected **";
        }

        if (isset($this->entropy['overall'])) {
            $lines[] = sprintf("Entropy: %.4f / 8.0", $this->entropy['overall']);
        }

        return implode("\n", $lines);
    }

    /**
     * JSON representation.
     */
    public function toJson(int $flags = 0): string
    {
        return json_encode($this->toArray(), $flags | JSON_UNESCAPED_SLASHES);
    }

    private function formatSize(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $size = (float) $bytes;
        while ($size >= 1024 && $i < count($units) - 1) {
            $size /= 1024;
            $i++;
        }
        return round($size, 2) . ' ' . $units[$i];
    }
}
