<?php

declare(strict_types=1);

namespace DetectItEasy\Scanner;

use DetectItEasy\Result\AnalysisResult;

/**
 * Deep scanner for archive and container formats.
 *
 * Refines ZIP-based formats (APK, JAR, IPA, DOCX, XLSX, etc.)
 * and analyzes archive metadata.
 */
class ArchiveScanner extends AbstractScanner
{
    public function deepScan(string $data, int $fileSize, AnalysisResult $result): void
    {
        $format = $result->getFileFormat();

        switch ($format) {
            case 'ZIP':
                $this->scanZip($data, $fileSize, $result);
                break;
            case 'RAR':
                $this->scanRar($data, $result);
                break;
            case '7z':
                $this->scan7z($data, $result);
                break;
            case 'GZIP':
                $this->scanGzip($data, $result);
                break;
            case 'BZIP2':
                $this->scanBzip2($data, $result);
                break;
            case 'XZ':
                $this->scanXz($data, $result);
                break;
            case 'CAB':
                $this->scanCab($data, $result);
                break;
        }
    }

    /**
     * Analyze a ZIP archive and refine the format if it's a known container.
     */
    private function scanZip(string $data, int $fileSize, AnalysisResult $result): void
    {
        // Extract central directory filenames for ZIP subtype detection
        $filenames = $this->extractZipFilenames($data);
        $result->setMetadata('zip_entries', count($filenames));

        // Android APK detection
        if (in_array('AndroidManifest.xml', $filenames) || in_array('classes.dex', $filenames)) {
            $result->setFileFormat([
                'format' => 'APK',
                'description' => 'Android Application Package',
                'mime_type' => 'application/vnd.android.package-archive',
            ]);
            $this->analyzeApk($filenames, $result);
            return;
        }

        // Java JAR detection
        if (in_array('META-INF/MANIFEST.MF', $filenames)) {
            // Could be JAR, WAR, or EAR
            $hasWebXml = in_array('WEB-INF/web.xml', $filenames);
            $hasAppXml = in_array('META-INF/application.xml', $filenames);

            if ($hasWebXml) {
                $result->setFileFormat([
                    'format' => 'WAR',
                    'description' => 'Java Web Application Archive',
                    'mime_type' => 'application/java-archive',
                ]);
            } elseif ($hasAppXml) {
                $result->setFileFormat([
                    'format' => 'EAR',
                    'description' => 'Java Enterprise Application Archive',
                    'mime_type' => 'application/java-archive',
                ]);
            } else {
                $result->setFileFormat([
                    'format' => 'JAR',
                    'description' => 'Java Archive',
                    'mime_type' => 'application/java-archive',
                ]);
            }
            return;
        }

        // iOS IPA detection
        if ($this->hasFileMatching($filenames, 'Payload/*.app/Info.plist')) {
            $result->setFileFormat([
                'format' => 'IPA',
                'description' => 'iOS Application Archive',
                'mime_type' => 'application/x-ios-app',
            ]);
            return;
        }

        // Office Open XML detection
        if (in_array('[Content_Types].xml', $filenames)) {
            // DOCX, XLSX, PPTX
            foreach ($filenames as $fn) {
                if (strpos($fn, 'word/') === 0) {
                    $result->setFileFormat([
                        'format' => 'DOCX',
                        'description' => 'Microsoft Word Document (OOXML)',
                        'mime_type' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    ]);
                    return;
                }
                if (strpos($fn, 'xl/') === 0) {
                    $result->setFileFormat([
                        'format' => 'XLSX',
                        'description' => 'Microsoft Excel Spreadsheet (OOXML)',
                        'mime_type' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    ]);
                    return;
                }
                if (strpos($fn, 'ppt/') === 0) {
                    $result->setFileFormat([
                        'format' => 'PPTX',
                        'description' => 'Microsoft PowerPoint Presentation (OOXML)',
                        'mime_type' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                    ]);
                    return;
                }
            }
        }

        // EPUB
        if (in_array('META-INF/container.xml', $filenames)) {
            $result->setFileFormat([
                'format' => 'EPUB',
                'description' => 'EPUB Electronic Publication',
                'mime_type' => 'application/epub+zip',
            ]);
            return;
        }

        // OpenDocument (ODT, ODS, ODP)
        if (in_array('content.xml', $filenames) && in_array('META-INF/manifest.xml', $filenames)) {
            // Check mimetype file content
            foreach ($filenames as $fn) {
                if ($fn === 'mimetype') {
                    $result->setFileFormat([
                        'format' => 'ODF',
                        'description' => 'OpenDocument Format',
                        'mime_type' => 'application/vnd.oasis.opendocument.text',
                    ]);
                    return;
                }
            }
        }

        // NuGet package
        foreach ($filenames as $fn) {
            if (preg_match('/\.nuspec$/', $fn)) {
                $result->setFileFormat([
                    'format' => 'NuGet',
                    'description' => 'NuGet Package',
                    'mime_type' => 'application/zip',
                ]);
                return;
            }
        }

        // Chrome Extension
        if (in_array('manifest.json', $filenames)) {
            // Heuristic: look for Chrome extension markers
            foreach ($filenames as $fn) {
                if (strpos($fn, '_locales/') === 0) {
                    $result->setFileFormat([
                        'format' => 'CRX',
                        'description' => 'Chrome Extension (unpacked ZIP)',
                        'mime_type' => 'application/x-chrome-extension',
                    ]);
                    return;
                }
            }
        }

        // Record some sample filenames for context
        $sampleFiles = array_slice($filenames, 0, 20);
        if (!empty($sampleFiles)) {
            $result->setMetadata('sample_files', $sampleFiles);
        }
    }

    /**
     * Analyze APK-specific contents.
     */
    private function analyzeApk(array $filenames, AnalysisResult $result): void
    {
        $hasNativeLibs = false;
        $architectures = [];
        $hasKotlin = false;
        $hasFlutter = false;
        $hasReactNative = false;
        $hasXamarin = false;
        $dexCount = 0;

        foreach ($filenames as $fn) {
            // Native libraries
            if (preg_match('#^lib/([\w-]+)/.*\.so$#', $fn, $m)) {
                $hasNativeLibs = true;
                $arch = $m[1];
                if (!in_array($arch, $architectures)) {
                    $architectures[] = $arch;
                }
            }

            // DEX files
            if (preg_match('/^classes\d*\.dex$/', $fn)) {
                $dexCount++;
            }

            // Kotlin
            if (strpos($fn, 'kotlin/') === 0 || strpos($fn, 'META-INF/kotlin') !== false) {
                $hasKotlin = true;
            }

            // Flutter
            if (strpos($fn, 'libflutter.so') !== false || strpos($fn, 'flutter_assets/') === 0) {
                $hasFlutter = true;
            }

            // React Native
            if (strpos($fn, 'libreactnative') !== false || $fn === 'assets/index.android.bundle') {
                $hasReactNative = true;
            }

            // Xamarin
            if (strpos($fn, 'libmonodroid') !== false || strpos($fn, 'assemblies/Xamarin') !== false) {
                $hasXamarin = true;
            }
        }

        $result->setMetadata('dex_count', $dexCount);
        $result->setMetadata('has_native_libs', $hasNativeLibs);

        if (!empty($architectures)) {
            $result->setMetadata('native_architectures', $architectures);
        }

        if ($dexCount > 1) {
            $result->setMetadata('multidex', true);
        }

        if ($hasKotlin) {
            $result->addDetection('compiler', 'Kotlin', '', 0.9, ['method' => 'apk_contents']);
        }
        if ($hasFlutter) {
            $result->addDetection('framework', 'Flutter', '', 0.95, ['method' => 'apk_contents']);
        }
        if ($hasReactNative) {
            $result->addDetection('framework', 'React Native', '', 0.9, ['method' => 'apk_contents']);
        }
        if ($hasXamarin) {
            $result->addDetection('framework', 'Xamarin', '', 0.9, ['method' => 'apk_contents']);
        }
    }

    /**
     * Extract filenames from a ZIP central directory.
     *
     * @return string[]
     */
    private function extractZipFilenames(string $data): array
    {
        $filenames = [];
        $dataLen = strlen($data);

        // Find End of Central Directory record
        $eocdPos = false;
        $searchStart = max(0, $dataLen - 65557); // EOCD can be at most 65557 bytes from end
        for ($i = $dataLen - 22; $i >= $searchStart; $i--) {
            if (substr($data, $i, 4) === "PK\x05\x06") {
                $eocdPos = $i;
                break;
            }
        }

        if ($eocdPos === false) {
            // Fallback: scan local file headers
            return $this->extractZipFilenamesFromLocal($data);
        }

        // Parse EOCD
        $cdOffset = $this->readUint32LE($data, $eocdPos + 16);
        $cdSize = $this->readUint32LE($data, $eocdPos + 12);
        $totalEntries = $this->readUint16LE($data, $eocdPos + 10);

        if ($cdOffset === 0 || $cdOffset >= $dataLen) {
            return $this->extractZipFilenamesFromLocal($data);
        }

        // Parse central directory
        $pos = $cdOffset;
        $limit = min($totalEntries, 1000); // Safety limit
        for ($i = 0; $i < $limit && $pos + 46 <= $dataLen; $i++) {
            if (substr($data, $pos, 4) !== "PK\x01\x02") {
                break;
            }

            $filenameLen = $this->readUint16LE($data, $pos + 28);
            $extraLen = $this->readUint16LE($data, $pos + 30);
            $commentLen = $this->readUint16LE($data, $pos + 32);

            if ($pos + 46 + $filenameLen > $dataLen) {
                break;
            }

            $filename = substr($data, $pos + 46, $filenameLen);
            $filenames[] = $filename;

            $pos += 46 + $filenameLen + $extraLen + $commentLen;
        }

        return $filenames;
    }

    /**
     * Fallback: extract filenames from local file headers.
     *
     * @return string[]
     */
    private function extractZipFilenamesFromLocal(string $data): array
    {
        $filenames = [];
        $dataLen = strlen($data);
        $pos = 0;
        $limit = 500;

        while ($pos + 30 <= $dataLen && count($filenames) < $limit) {
            if (substr($data, $pos, 4) !== "PK\x03\x04") {
                break;
            }

            $filenameLen = $this->readUint16LE($data, $pos + 26);
            $extraLen = $this->readUint16LE($data, $pos + 28);
            $compressedSize = $this->readUint32LE($data, $pos + 18);

            if ($pos + 30 + $filenameLen > $dataLen) {
                break;
            }

            $filename = substr($data, $pos + 30, $filenameLen);
            $filenames[] = $filename;

            $pos += 30 + $filenameLen + $extraLen + $compressedSize;
        }

        return $filenames;
    }

    /**
     * Check if any filename matches a glob-like pattern.
     */
    private function hasFileMatching(array $filenames, string $pattern): bool
    {
        $escaped = preg_quote($pattern, '#');
        $regex = '#^' . str_replace(['\\*', '\\?'], ['[^/]*', '.'], $escaped) . '$#';
        foreach ($filenames as $fn) {
            if (preg_match($regex, $fn)) {
                return true;
            }
        }
        return false;
    }

    private function scanRar(string $data, AnalysisResult $result): void
    {
        // Detect RAR version
        if (strlen($data) >= 8 && substr($data, 0, 8) === "Rar!\x1A\x07\x01\x00") {
            $result->setMetadata('rar_version', 5);
        } else {
            $result->setMetadata('rar_version', 4);
        }

        // Check for encryption
        if (strlen($data) >= 12) {
            // RAR4: flag at byte 10 in archive header
            $flags = $this->readUint16LE($data, 10);
            if ($flags & 0x0080) {
                $result->setMetadata('encrypted', true);
            }
        }
    }

    private function scan7z(string $data, AnalysisResult $result): void
    {
        if (strlen($data) >= 12) {
            $majorVersion = ord($data[6]);
            $minorVersion = ord($data[7]);
            $result->setMetadata('7z_version', "{$majorVersion}.{$minorVersion}");
        }
    }

    private function scanGzip(string $data, AnalysisResult $result): void
    {
        if (strlen($data) < 10) {
            return;
        }

        $method = ord($data[2]);
        $flags = ord($data[3]);

        $result->setMetadata('compression_method', $method === 8 ? 'deflate' : "unknown({$method})");

        // Check for original filename (FNAME flag)
        if ($flags & 0x08) {
            $nameStart = 10;
            // Skip FEXTRA if present
            if ($flags & 0x04 && strlen($data) >= 12) {
                $extraLen = $this->readUint16LE($data, 10);
                $nameStart = 12 + $extraLen;
            }
            if ($nameStart < strlen($data)) {
                $origName = $this->readString($data, $nameStart, 256);
                if ($origName !== '') {
                    $result->setMetadata('original_filename', $origName);

                    // Detect tar.gz
                    if (preg_match('/\.tar$/', $origName)) {
                        $result->setFileFormat([
                            'format' => 'TAR.GZ',
                            'description' => 'GZIP Compressed TAR Archive',
                            'mime_type' => 'application/gzip',
                        ]);
                    }
                }
            }
        }
    }

    private function scanBzip2(string $data, AnalysisResult $result): void
    {
        if (strlen($data) >= 4) {
            $blockSize = ord($data[3]) - ord('0');
            if ($blockSize >= 1 && $blockSize <= 9) {
                $result->setMetadata('block_size', $blockSize * 100000);
            }
        }
    }

    private function scanXz(string $data, AnalysisResult $result): void
    {
        $result->setMetadata('compression', 'XZ/LZMA2');
    }

    private function scanCab(string $data, AnalysisResult $result): void
    {
        if (strlen($data) >= 36) {
            $cabinetSize = $this->readUint32LE($data, 8);
            $fileCount = $this->readUint16LE($data, 28);
            $versionMinor = ord($data[24]);
            $versionMajor = ord($data[25]);

            $result->setMetadata('cabinet_size', $cabinetSize);
            $result->setMetadata('file_count', $fileCount);
            $result->setMetadata('cab_version', "{$versionMajor}.{$versionMinor}");
        }
    }
}
