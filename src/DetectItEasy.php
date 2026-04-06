<?php

declare(strict_types=1);

namespace DetectItEasy;

use DetectItEasy\Result\AnalysisResult;
use DetectItEasy\Scanner\PEScanner;
use DetectItEasy\Scanner\ELFScanner;
use DetectItEasy\Scanner\MachOScanner;
use DetectItEasy\Scanner\ArchiveScanner;
use DetectItEasy\Scanner\MagicBytesScanner;
use DetectItEasy\Heuristic\EntropyAnalyzer;
use DetectItEasy\Signature\SignatureDatabase;

/**
 * DetectItEasy - Universal file type detection library.
 *
 * Identifies file types, packers, compilers, protectors, and more
 * through signature matching and heuristic analysis.
 */
class DetectItEasy
{
    /** @var SignatureDatabase */
    private $signatureDb;

    /** @var EntropyAnalyzer */
    private $entropyAnalyzer;

    /** @var MagicBytesScanner */
    private $magicScanner;

    /** @var PEScanner */
    private $peScanner;

    /** @var ELFScanner */
    private $elfScanner;

    /** @var MachOScanner */
    private $machOScanner;

    /** @var ArchiveScanner */
    private $archiveScanner;

    /** @var array<string, mixed> */
    private $options;

    /**
     * @param array<string, mixed> $options Configuration options:
     *   - signatures_path: string  Custom path to signature database directory
     *   - deep_scan: bool          Enable deep heuristic analysis (default: true)
     *   - entropy_analysis: bool   Enable entropy analysis (default: true)
     *   - max_read_size: int       Max bytes to read for analysis (default: 10MB)
     */
    public function __construct(array $options = [])
    {
        $this->options = array_merge([
            'signatures_path' => null,
            'deep_scan' => true,
            'entropy_analysis' => true,
            'max_read_size' => 10 * 1024 * 1024,
        ], $options);

        $sigPath = $this->options['signatures_path']
            ?? dirname(__DIR__) . '/signatures';

        $this->signatureDb = new SignatureDatabase($sigPath);
        $this->entropyAnalyzer = new EntropyAnalyzer();
        $this->magicScanner = new MagicBytesScanner($this->signatureDb);
        $this->peScanner = new PEScanner($this->signatureDb);
        $this->elfScanner = new ELFScanner($this->signatureDb);
        $this->machOScanner = new MachOScanner($this->signatureDb);
        $this->archiveScanner = new ArchiveScanner($this->signatureDb);
    }

    /**
     * Analyze a file and return detection results.
     *
     * @param string $filePath Path to the file to analyze.
     * @return AnalysisResult
     * @throws \InvalidArgumentException If file is not readable.
     */
    public function analyze(string $filePath): AnalysisResult
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            throw new \InvalidArgumentException(
                "File not found or not readable: {$filePath}"
            );
        }

        $fileSize = filesize($filePath);
        $readSize = min($fileSize, $this->options['max_read_size']);

        $handle = fopen($filePath, 'rb');
        if ($handle === false) {
            throw new \RuntimeException("Failed to open file: {$filePath}");
        }

        $data = fread($handle, $readSize);
        fclose($handle);

        if ($data === false) {
            throw new \RuntimeException("Failed to read file: {$filePath}");
        }

        $result = new AnalysisResult($filePath, $fileSize);

        // Step 1: Magic bytes identification
        $formatDetection = $this->magicScanner->scan($data, $fileSize);
        $result->setFileFormat($formatDetection);

        // Step 2: Format-specific deep analysis
        $format = $result->getFileFormat();
        if ($this->options['deep_scan'] && $format !== null) {
            $this->runFormatScanner($format, $data, $fileSize, $result);
        }

        // Step 3: Entropy analysis
        if ($this->options['entropy_analysis']) {
            $entropy = $this->entropyAnalyzer->analyze($data);
            $result->setEntropy($entropy);
        }

        return $result;
    }

    /**
     * Quick scan - only identifies file format, no deep analysis.
     *
     * @param string $filePath
     * @return AnalysisResult
     */
    public function quickScan(string $filePath): AnalysisResult
    {
        $originalDeep = $this->options['deep_scan'];
        $originalEntropy = $this->options['entropy_analysis'];
        $this->options['deep_scan'] = false;
        $this->options['entropy_analysis'] = false;

        try {
            return $this->analyze($filePath);
        } finally {
            $this->options['deep_scan'] = $originalDeep;
            $this->options['entropy_analysis'] = $originalEntropy;
        }
    }

    /**
     * Analyze raw binary data (no file path needed).
     *
     * @param string $data Raw binary data.
     * @param string $label Optional label for the result.
     * @return AnalysisResult
     */
    public function analyzeData(string $data, string $label = '<memory>'): AnalysisResult
    {
        $fileSize = strlen($data);
        $result = new AnalysisResult($label, $fileSize);

        $formatDetection = $this->magicScanner->scan($data, $fileSize);
        $result->setFileFormat($formatDetection);

        $format = $result->getFileFormat();
        if ($this->options['deep_scan'] && $format !== null) {
            $this->runFormatScanner($format, $data, $fileSize, $result);
        }

        if ($this->options['entropy_analysis']) {
            $entropy = $this->entropyAnalyzer->analyze($data);
            $result->setEntropy($entropy);
        }

        return $result;
    }

    /**
     * Batch analyze multiple files.
     *
     * @param string[] $filePaths
     * @return AnalysisResult[]
     */
    public function batchAnalyze(array $filePaths): array
    {
        $results = [];
        foreach ($filePaths as $path) {
            try {
                $results[$path] = $this->analyze($path);
            } catch (\Exception $e) {
                $result = new AnalysisResult($path, 0);
                $result->setError($e->getMessage());
                $results[$path] = $result;
            }
        }
        return $results;
    }

    /**
     * Run the appropriate format-specific scanner.
     */
    private function runFormatScanner(
        string $format,
        string $data,
        int $fileSize,
        AnalysisResult $result
    ): void {
        switch ($format) {
            case 'PE':
            case 'PE64':
                $this->peScanner->deepScan($data, $fileSize, $result);
                break;
            case 'ELF':
            case 'ELF64':
                $this->elfScanner->deepScan($data, $fileSize, $result);
                break;
            case 'Mach-O':
            case 'Mach-O 64':
            case 'Mach-O Universal':
                $this->machOScanner->deepScan($data, $fileSize, $result);
                break;
            case 'ZIP':
            case 'APK':
            case 'JAR':
            case 'IPA':
            case 'DOCX':
            case 'XLSX':
            case 'RAR':
            case '7z':
            case 'GZIP':
            case 'BZIP2':
            case 'XZ':
            case 'TAR':
            case 'CAB':
                $this->archiveScanner->deepScan($data, $fileSize, $result);
                break;
        }
    }

    /**
     * Get the signature database instance.
     */
    public function getSignatureDatabase(): SignatureDatabase
    {
        return $this->signatureDb;
    }
}
