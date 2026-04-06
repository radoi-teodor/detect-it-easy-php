<?php

declare(strict_types=1);

namespace DetectItEasy\Tests;

use PHPUnit\Framework\TestCase;
use DetectItEasy\DetectItEasy;
use DetectItEasy\Result\AnalysisResult;
use DetectItEasy\Heuristic\EntropyAnalyzer;

class DetectItEasyTest extends TestCase
{
    /** @var DetectItEasy */
    private $die;

    protected function setUp(): void
    {
        $this->die = new DetectItEasy();
    }

    // ---- Format Detection via analyzeData ----

    public function testDetectPE(): void
    {
        // Minimal PE: MZ header + PE signature at offset 0x3C
        $data = "MZ" . str_repeat("\x00", 58) . "\x80\x00\x00\x00"; // e_lfanew = 0x80
        $data .= str_repeat("\x00", 128 - strlen($data)); // Pad to PE offset
        $data .= "PE\x00\x00"; // PE signature
        $data .= str_repeat("\x00", 256); // Padding for headers

        $result = $this->die->analyzeData($data, 'test.exe');
        $this->assertContains($result->getFileFormat(), ['PE', 'PE64', 'MS-DOS']);
    }

    public function testDetectELF(): void
    {
        // ELF header
        $data = "\x7FELF" . "\x02\x01\x01\x00"; // 64-bit, little-endian, System V
        $data .= str_repeat("\x00", 8); // padding
        $data .= "\x02\x00"; // ET_EXEC
        $data .= "\x3E\x00"; // x86-64
        $data .= str_repeat("\x00", 256);

        $result = $this->die->analyzeData($data, 'test.elf');
        $this->assertContains($result->getFileFormat(), ['ELF', 'ELF64']);
    }

    public function testDetectMachO(): void
    {
        // Mach-O 64-bit magic (little-endian)
        $data = "\xCF\xFA\xED\xFE";
        $data .= str_repeat("\x00", 256);

        $result = $this->die->analyzeData($data, 'test.macho');
        $this->assertEquals('Mach-O 64', $result->getFileFormat());
    }

    public function testDetectZIP(): void
    {
        $data = "PK\x03\x04" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.zip');
        // ZIP or a refined subtype (APK, JAR, etc.)
        $this->assertNotNull($result->getFileFormat());
    }

    public function testDetectPDF(): void
    {
        $data = "%PDF-1.7\n" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.pdf');
        $this->assertEquals('PDF', $result->getFileFormat());
    }

    public function testDetectPNG(): void
    {
        $data = "\x89PNG\r\n\x1A\n" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.png');
        $this->assertEquals('PNG', $result->getFileFormat());
    }

    public function testDetectJPEG(): void
    {
        $data = "\xFF\xD8\xFF\xE0" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.jpg');
        $this->assertEquals('JPEG', $result->getFileFormat());
    }

    public function testDetectGZIP(): void
    {
        $data = "\x1F\x8B\x08\x00" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.gz');
        $this->assertEquals('GZIP', $result->getFileFormat());
    }

    public function testDetect7z(): void
    {
        $data = "7z\xBC\xAF\x27\x1C\x00\x04" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.7z');
        $this->assertEquals('7z', $result->getFileFormat());
    }

    public function testDetectRAR(): void
    {
        $data = "Rar!\x1A\x07\x00" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.rar');
        $this->assertEquals('RAR', $result->getFileFormat());
    }

    public function testDetectSQLite(): void
    {
        $data = "SQLite format 3\x00" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.db');
        $this->assertEquals('SQLite', $result->getFileFormat());
    }

    public function testDetectWASM(): void
    {
        $data = "\x00asm\x01\x00\x00\x00" . str_repeat("\x00", 256);
        $result = $this->die->analyzeData($data, 'test.wasm');
        $this->assertEquals('WASM', $result->getFileFormat());
    }

    public function testUnknownFormat(): void
    {
        $data = str_repeat("\xFF", 256);
        $result = $this->die->analyzeData($data, 'unknown.bin');
        $this->assertNull($result->getFileFormat());
    }

    // ---- PE Deep Scan Heuristics ----

    public function testDetectUPXPacked(): void
    {
        // Build a minimal PE with UPX section names
        $data = $this->buildMinimalPE();
        // Inject UPX markers
        $data .= "UPX0\x00\x00\x00\x00" . str_repeat("\x00", 32);
        $data .= "UPX1\x00\x00\x00\x00" . str_repeat("\x00", 32);
        $data .= "UPX!" . str_repeat("\x00", 128);

        $result = $this->die->analyzeData($data, 'upx_packed.exe');
        $packers = $result->getDetectionsByCategory('packer');
        $names = array_column($packers, 'name');
        $this->assertTrue(
            in_array('UPX', $names) || count($packers) > 0,
            'Should detect UPX packer'
        );
    }

    public function testDetectDotNet(): void
    {
        $data = $this->buildMinimalPE();
        $data .= "mscoree.dll\x00_CorExeMain\x00v4.0.30319\x00";
        $data .= str_repeat("\x00", 256);

        $result = $this->die->analyzeData($data, 'dotnet.exe');
        $compilers = $result->getDetectionsByCategory('compiler');
        $names = array_column($compilers, 'name');
        $this->assertTrue(
            in_array('Microsoft .NET', $names),
            'Should detect .NET'
        );
    }

    // ---- Entropy Analyzer ----

    public function testEntropyLowForUniformData(): void
    {
        $analyzer = new EntropyAnalyzer();
        $data = str_repeat("\x00", 1024);
        $result = $analyzer->analyze($data);

        $this->assertLessThan(0.1, $result['overall']);
        $this->assertEquals('very_low', $result['assessment']);
    }

    public function testEntropyHighForRandomData(): void
    {
        $analyzer = new EntropyAnalyzer();
        // Pseudo-random data
        $data = '';
        for ($i = 0; $i < 4096; $i++) {
            $data .= chr($i % 256);
        }
        $result = $analyzer->analyze($data);

        $this->assertGreaterThan(7.0, $result['overall']);
    }

    public function testEntropyEmptyData(): void
    {
        $analyzer = new EntropyAnalyzer();
        $result = $analyzer->analyze('');

        $this->assertEquals(0.0, $result['overall']);
        $this->assertEquals('empty', $result['assessment']);
    }

    // ---- AnalysisResult ----

    public function testResultToArray(): void
    {
        $result = new AnalysisResult('/test/file.bin', 1024);
        $result->setFileFormat([
            'format' => 'PE',
            'description' => 'Windows PE Executable',
            'mime_type' => 'application/vnd.microsoft.portable-executable',
        ]);
        $result->addDetection('compiler', 'GCC', '12.0', 0.9);

        $array = $result->toArray();
        $this->assertEquals('PE', $array['format']);
        $this->assertEquals(1024, $array['size']);
        $this->assertArrayHasKey('detections', $array);
        $this->assertArrayHasKey('compiler', $array['detections']);
    }

    public function testResultIsPacked(): void
    {
        $result = new AnalysisResult('/test/file.bin', 1024);
        $this->assertFalse($result->isPacked());

        $result->addDetection('packer', 'UPX', '3.96', 0.95);
        $this->assertTrue($result->isPacked());
    }

    public function testResultIsPackedByEntropy(): void
    {
        $result = new AnalysisResult('/test/file.bin', 1024);
        $result->setFileFormat([
            'format' => 'PE',
            'description' => 'Windows PE Executable',
            'mime_type' => 'application/vnd.microsoft.portable-executable',
        ]);
        $result->setEntropy(['overall' => 7.5]);
        $this->assertTrue($result->isPacked());
    }

    public function testNonExecutableHighEntropyNotPacked(): void
    {
        $result = new AnalysisResult('/test/archive.zip', 1024);
        $result->setFileFormat([
            'format' => 'ZIP',
            'description' => 'ZIP Archive',
            'mime_type' => 'application/zip',
        ]);
        $result->setEntropy(['overall' => 7.9]);
        $this->assertFalse($result->isPacked());
    }

    public function testResultSummary(): void
    {
        $result = new AnalysisResult('/test/file.exe', 2048);
        $result->setFileFormat([
            'format' => 'PE',
            'description' => 'Windows PE Executable',
            'mime_type' => 'application/vnd.microsoft.portable-executable',
        ]);

        $summary = $result->getSummary();
        $this->assertStringContainsString('Windows PE Executable', $summary);
        $this->assertStringContainsString('2 KB', $summary);
    }

    public function testResultJson(): void
    {
        $result = new AnalysisResult('/test/file.bin', 512);
        $json = $result->toJson();
        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);
        $this->assertEquals(512, $decoded['size']);
    }

    public function testResultError(): void
    {
        $result = new AnalysisResult('/bad/file', 0);
        $result->setError('File not found');

        $this->assertTrue($result->hasError());
        $this->assertEquals('File not found', $result->getError());
        $this->assertStringContainsString('Error:', $result->getSummary());
    }

    // ---- Quick Scan ----

    public function testQuickScanSkipsDeepAnalysis(): void
    {
        $data = "\x89PNG\r\n\x1A\n" . str_repeat("\x00", 256);

        // Write temp file
        $tmp = tempnam(sys_get_temp_dir(), 'die_test_');
        file_put_contents($tmp, $data);

        try {
            $result = $this->die->quickScan($tmp);
            $this->assertEquals('PNG', $result->getFileFormat());
            $this->assertEmpty($result->getEntropy());
        } finally {
            @unlink($tmp);
        }
    }

    // ---- Batch Analysis ----

    public function testBatchAnalyze(): void
    {
        $tmp1 = tempnam(sys_get_temp_dir(), 'die_batch_');
        $tmp2 = tempnam(sys_get_temp_dir(), 'die_batch_');
        file_put_contents($tmp1, "%PDF-1.4\n" . str_repeat("\x00", 64));
        file_put_contents($tmp2, "\x89PNG\r\n\x1A\n" . str_repeat("\x00", 64));

        try {
            $results = $this->die->batchAnalyze([$tmp1, $tmp2]);
            $this->assertCount(2, $results);
            $this->assertEquals('PDF', $results[$tmp1]->getFileFormat());
            $this->assertEquals('PNG', $results[$tmp2]->getFileFormat());
        } finally {
            @unlink($tmp1);
            @unlink($tmp2);
        }
    }

    public function testBatchAnalyzeWithBadFile(): void
    {
        $results = $this->die->batchAnalyze(['/nonexistent/file.bin']);
        $this->assertCount(1, $results);
        $result = reset($results);
        $this->assertTrue($result->hasError());
    }

    // ---- Helpers ----

    /**
     * Build a minimal valid PE binary for testing.
     */
    private function buildMinimalPE(): string
    {
        // DOS header
        $dos = "MZ" . str_repeat("\x00", 58);
        $dos .= pack('V', 128); // e_lfanew = 0x80
        $dos .= str_repeat("\x00", 128 - strlen($dos));

        // PE signature
        $pe = "PE\x00\x00";

        // COFF header: i386, 1 section, size of optional = 0xE0
        $coff = pack('v', 0x014C); // Machine: i386
        $coff .= pack('v', 1);     // NumberOfSections
        $coff .= pack('V', 0);     // TimeDateStamp
        $coff .= pack('V', 0);     // PointerToSymbolTable
        $coff .= pack('V', 0);     // NumberOfSymbols
        $coff .= pack('v', 0xE0);  // SizeOfOptionalHeader
        $coff .= pack('v', 0x0102); // Characteristics: EXECUTABLE_IMAGE

        // Optional header (PE32)
        $opt = pack('v', 0x010B); // Magic: PE32
        $opt .= "\x0E\x00";       // LinkerVersion 14.0
        $opt .= str_repeat("\x00", 0xE0 - 4); // Rest of optional header

        // Section header: .text
        $sec = ".text\x00\x00\x00"; // Name
        $sec .= pack('V', 0x1000);  // VirtualSize
        $sec .= pack('V', 0x1000);  // VirtualAddress
        $sec .= pack('V', 0x200);   // SizeOfRawData
        $sec .= pack('V', 0x200);   // PointerToRawData
        $sec .= str_repeat("\x00", 12); // Relocations, LineNumbers
        $sec .= pack('V', 0x60000020); // Characteristics: CODE|EXECUTE|READ

        return $dos . $pe . $coff . $opt . $sec;
    }
}
