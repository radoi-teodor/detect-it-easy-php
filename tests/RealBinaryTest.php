<?php

declare(strict_types=1);

namespace DetectItEasy\Tests;

use PHPUnit\Framework\TestCase;
use DetectItEasy\DetectItEasy;

/**
 * Integration tests using real downloaded binaries.
 *
 * These tests require the test_samples/ directory to be populated.
 * Run: php bin/download-samples (or see README for manual download instructions).
 */
class RealBinaryTest extends TestCase
{
    /** @var DetectItEasy */
    private $die;

    /** @var string */
    private $samplesDir;

    protected function setUp(): void
    {
        $this->samplesDir = dirname(__DIR__) . '/test_samples';
        if (!is_dir($this->samplesDir)) {
            $this->markTestSkipped('test_samples/ directory not found. Download samples first.');
        }
        $this->die = new DetectItEasy();
    }

    private function getSample(string $name): string
    {
        $path = $this->samplesDir . '/' . $name;
        if (!is_file($path)) {
            $this->markTestSkipped("Sample file not found: {$name}");
        }
        return $path;
    }

    // =========================================================================
    // PE Executables
    // =========================================================================

    /**
     * UPX-packed PE64 binary (the UPX tool itself).
     */
    public function testUpxPackedExe(): void
    {
        $result = $this->die->analyze($this->getSample('upx.exe'));

        $this->assertContains($result->getFileFormat(), ['PE', 'PE64']);
        $this->assertTrue($result->isPacked(), 'UPX binary should be detected as packed');

        $packers = $result->getDetectionsByCategory('packer');
        $packerNames = array_column($packers, 'name');
        $this->assertContains('UPX', $packerNames, 'Should detect UPX packer');

        // High entropy expected for packed binary
        $entropy = $result->getEntropy();
        $this->assertGreaterThan(7.0, $entropy['overall']);
    }

    /**
     * .NET executable (NuGet.exe).
     */
    public function testDotNetExe(): void
    {
        $result = $this->die->analyze($this->getSample('nuget.exe'));

        $this->assertContains($result->getFileFormat(), ['PE', 'PE64']);

        $compilers = $result->getDetectionsByCategory('compiler');
        $compilerNames = array_column($compilers, 'name');
        $this->assertContains('Microsoft .NET', $compilerNames, 'Should detect .NET framework');

        // Should have .NET runtime metadata
        $meta = $result->getMetadata();
        $this->assertNotNull($meta);
    }

    /**
     * Go-compiled PE64 binary (lazygit).
     */
    public function testGoCompiledExe(): void
    {
        $result = $this->die->analyze($this->getSample('lazygit.exe'));

        $this->assertEquals('PE64', $result->getFileFormat());

        $compilers = $result->getDetectionsByCategory('compiler');
        $compilerNames = array_column($compilers, 'name');
        $this->assertContains('Go (Golang)', $compilerNames, 'Should detect Go compiler');

        $this->assertEquals('AMD64 (x86-64)', $result->getMetadata('machine'));
        $this->assertTrue($result->getMetadata('is_64bit'));
    }

    /**
     * Rust-compiled PE64 binary (ripgrep).
     */
    public function testRustCompiledExe(): void
    {
        $result = $this->die->analyze($this->getSample('rg.exe'));

        $this->assertEquals('PE64', $result->getFileFormat());

        $compilers = $result->getDetectionsByCategory('compiler');
        $compilerNames = array_column($compilers, 'name');
        $this->assertContains('Rust', $compilerNames, 'Should detect Rust compiler');
    }

    /**
     * PyInstaller-compiled PE64 binary (yt-dlp).
     */
    public function testPyInstallerExe(): void
    {
        $result = $this->die->analyze($this->getSample('yt-dlp.exe'));

        $this->assertEquals('PE64', $result->getFileFormat());
        $this->assertTrue($result->isPacked(), 'PyInstaller binary should be detected as packed');

        $packers = $result->getDetectionsByCategory('packer');
        $packerNames = array_column($packers, 'name');
        $this->assertContains('PyInstaller', $packerNames, 'Should detect PyInstaller packer');

        $compilers = $result->getDetectionsByCategory('compiler');
        $compilerNames = array_column($compilers, 'name');
        $this->assertContains('MinGW/GCC', $compilerNames, 'Should detect MinGW/GCC (PyInstaller uses it)');

        // Very high entropy expected
        $entropy = $result->getEntropy();
        $this->assertGreaterThan(7.5, $entropy['overall']);
    }

    /**
     * Windows system binary (notepad.exe) - MSVC compiled.
     */
    public function testWindowsNotepad(): void
    {
        $notepad = 'C:/Windows/System32/notepad.exe';
        if (!is_file($notepad)) {
            $this->markTestSkipped('notepad.exe not found (non-Windows system)');
        }

        $result = $this->die->analyze($notepad);

        $this->assertEquals('PE64', $result->getFileFormat());
        $this->assertFalse($result->isPacked(), 'notepad.exe should not be packed');

        // Should have Rich header
        $this->assertTrue($result->getMetadata('rich_header'), 'Should have Rich header');

        // Should detect MSVC compiler
        $compilers = $result->getDetectionsByCategory('compiler');
        $this->assertNotEmpty($compilers, 'Should detect at least one compiler');

        // Should be Windows GUI subsystem
        $this->assertEquals('Windows GUI', $result->getMetadata('subsystem'));
    }

    // =========================================================================
    // ELF Binary
    // =========================================================================

    /**
     * ELF 64-bit Linux binary (GitHub CLI).
     */
    public function testElfBinary(): void
    {
        $result = $this->die->analyze($this->getSample('gh-linux-elf'));

        $this->assertEquals('ELF64', $result->getFileFormat());
        $this->assertEquals('64-bit', $result->getMetadata('elf_class'));
        $this->assertEquals('little-endian', $result->getMetadata('endianness'));
        $this->assertEquals('x86-64 (AMD64)', $result->getMetadata('machine'));
        $this->assertNotNull($result->getMetadata('entry_point'));
    }

    // =========================================================================
    // Mach-O Binary
    // =========================================================================

    /**
     * Mach-O ARM64 macOS binary (GitHub CLI for macOS).
     */
    public function testMachOBinary(): void
    {
        $result = $this->die->analyze($this->getSample('gh-macos-arm64'));

        $this->assertContains($result->getFileFormat(), ['Mach-O', 'Mach-O 64']);

        $compilers = $result->getDetectionsByCategory('compiler');
        $compilerNames = array_column($compilers, 'name');
        $this->assertContains('Go (Golang)', $compilerNames, 'Should detect Go compiler');
    }

    // =========================================================================
    // Archive / Container Formats
    // =========================================================================

    /**
     * Java JAR file (JUnit console standalone).
     */
    public function testJarFile(): void
    {
        $result = $this->die->analyze($this->getSample('junit-console.jar'));

        $this->assertEquals('JAR', $result->getFileFormat());
        $this->assertStringContainsString('Java', $result->getFormatDescription());
        $this->assertFalse($result->isPacked(), 'JAR files should not be marked as packed');

        $zipEntries = $result->getMetadata('zip_entries');
        $this->assertNotNull($zipEntries);
        $this->assertGreaterThan(0, $zipEntries);
    }

    /**
     * Android APK file (F-Droid).
     */
    public function testApkFile(): void
    {
        $result = $this->die->analyze($this->getSample('fdroid.apk'));

        $this->assertEquals('APK', $result->getFileFormat());
        $this->assertStringContainsString('Android', $result->getFormatDescription());

        // Should detect Kotlin
        $compilers = $result->getDetectionsByCategory('compiler');
        $compilerNames = array_column($compilers, 'name');
        $this->assertContains('Kotlin', $compilerNames, 'F-Droid APK should detect Kotlin');

        // Should have DEX count
        $dexCount = $result->getMetadata('dex_count');
        $this->assertNotNull($dexCount);
        $this->assertGreaterThanOrEqual(1, $dexCount);
    }

    // =========================================================================
    // Documents
    // =========================================================================

    /**
     * PDF document.
     */
    public function testPdfFile(): void
    {
        $result = $this->die->analyze($this->getSample('sample.pdf'));

        $this->assertEquals('PDF', $result->getFileFormat());
        $this->assertEquals('application/pdf', $result->getMimeType());
        $this->assertFalse($result->isPacked(), 'PDF should not be marked as packed');
    }

    // =========================================================================
    // Cross-cutting concerns
    // =========================================================================

    /**
     * Batch analysis should work on all samples without crashing.
     */
    public function testBatchAllSamples(): void
    {
        $files = glob($this->samplesDir . '/*');
        $this->assertNotEmpty($files);

        $results = $this->die->batchAnalyze($files);

        $this->assertCount(count($files), $results);

        foreach ($results as $path => $result) {
            $this->assertFalse($result->hasError(), "Error analyzing {$path}: " . ($result->getError() ?? ''));
            $this->assertNotNull($result->getFileFormat(), "Should detect format for {$path}");
        }
    }

    /**
     * Quick scan should correctly identify all sample formats.
     */
    public function testQuickScanAllSamples(): void
    {
        $expectedFormats = [
            'upx.exe' => ['PE', 'PE64'],
            'nuget.exe' => ['PE', 'PE64'],
            'lazygit.exe' => ['PE', 'PE64'],
            'rg.exe' => ['PE', 'PE64'],
            'yt-dlp.exe' => ['PE', 'PE64'],
            'gh-linux-elf' => ['ELF', 'ELF64'],
            'gh-macos-arm64' => ['Mach-O', 'Mach-O 64'],
            'fdroid.apk' => ['ZIP', 'APK'], // Quick scan won't refine ZIP subtypes
            'junit-console.jar' => ['ZIP', 'JAR'],
            'sample.pdf' => ['PDF'],
        ];

        foreach ($expectedFormats as $filename => $validFormats) {
            $path = $this->samplesDir . '/' . $filename;
            if (!is_file($path)) {
                continue;
            }

            $result = $this->die->quickScan($path);
            $this->assertContains(
                $result->getFileFormat(),
                $validFormats,
                "Quick scan of {$filename}: expected one of [" . implode(', ', $validFormats)
                    . "] but got " . ($result->getFileFormat() ?? 'null')
            );
        }
    }

    /**
     * JSON output should be valid for all samples.
     */
    public function testJsonOutputAllSamples(): void
    {
        $files = glob($this->samplesDir . '/*');
        foreach ($files as $path) {
            $result = $this->die->analyze($path);
            $json = $result->toJson();
            $decoded = json_decode($json, true);
            $this->assertIsArray($decoded, "JSON output should be valid for " . basename($path));
            $this->assertArrayHasKey('format', $decoded);
            $this->assertArrayHasKey('size', $decoded);
        }
    }

    /**
     * Entropy values should be sane for all samples.
     */
    public function testEntropyAllSamples(): void
    {
        $files = glob($this->samplesDir . '/*');
        foreach ($files as $path) {
            $result = $this->die->analyze($path);
            $entropy = $result->getEntropy();

            $this->assertArrayHasKey('overall', $entropy, "Should have entropy for " . basename($path));
            $this->assertGreaterThanOrEqual(0.0, $entropy['overall']);
            $this->assertLessThanOrEqual(8.0, $entropy['overall']);
            $this->assertArrayHasKey('assessment', $entropy);
        }
    }
}
