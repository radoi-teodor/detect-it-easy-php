<?php

/**
 * DetectItEasy-PHP — Web Demo
 *
 * Upload a file and get detailed analysis results.
 * Run with: php -S localhost:8080 -t public/
 */

require __DIR__ . '/../vendor/autoload.php';

use DetectItEasy\DetectItEasy;

$result = null;
$error = null;
$uploadedName = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errorMessages = [
            UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize directive.',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE form directive.',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded.',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder.',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
        ];
        $error = $errorMessages[$file['error']] ?? 'Unknown upload error.';
    } else {
        $uploadedName = basename($file['name']);
        try {
            $die = new DetectItEasy([
                'max_read_size' => 10 * 1024 * 1024,
            ]);
            $result = $die->analyze($file['tmp_name']);
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }
    }
}

function esc(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function formatSize(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $size = (float) $bytes;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return round($size, 2) . ' ' . $units[$i];
}

function confidenceBar(float $confidence): string
{
    $pct = (int) round($confidence * 100);
    $color = $pct >= 90 ? '#22c55e' : ($pct >= 70 ? '#eab308' : '#f97316');
    return '<div class="conf-bar"><div class="conf-fill" style="width:' . $pct . '%;background:' . $color . '"></div><span>' . $pct . '%</span></div>';
}

function entropyColor(float $entropy): string
{
    if ($entropy < 3.0) return '#22c55e';
    if ($entropy < 5.0) return '#84cc16';
    if ($entropy < 6.5) return '#eab308';
    if ($entropy < 7.2) return '#f97316';
    return '#ef4444';
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DetectItEasy-PHP &mdash; File Analyzer</title>
    <style>
        :root {
            --bg: #0f1117;
            --surface: #1a1d27;
            --surface2: #242836;
            --border: #2e3348;
            --text: #e4e7f1;
            --muted: #8b90a5;
            --accent: #6366f1;
            --accent2: #818cf8;
            --green: #22c55e;
            --red: #ef4444;
            --yellow: #eab308;
            --orange: #f97316;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.6;
        }
        .container {
            max-width: 960px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }
        header {
            text-align: center;
            margin-bottom: 2.5rem;
        }
        header h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        header p {
            color: var(--muted);
            margin-top: 0.3rem;
            font-size: 0.95rem;
        }

        /* Upload area */
        .upload-card {
            background: var(--surface);
            border: 2px dashed var(--border);
            border-radius: 12px;
            padding: 2.5rem;
            text-align: center;
            transition: border-color 0.2s, background 0.2s;
            position: relative;
        }
        .upload-card.dragover {
            border-color: var(--accent);
            background: rgba(99, 102, 241, 0.05);
        }
        .upload-card svg {
            width: 48px;
            height: 48px;
            color: var(--muted);
            margin-bottom: 1rem;
        }
        .upload-card h2 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.3rem;
        }
        .upload-card .hint {
            color: var(--muted);
            font-size: 0.85rem;
        }
        .upload-card input[type=file] {
            position: absolute;
            inset: 0;
            opacity: 0;
            cursor: pointer;
        }
        .btn {
            display: inline-block;
            margin-top: 1.2rem;
            padding: 0.65rem 2rem;
            background: var(--accent);
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn:hover { background: var(--accent2); }
        #file-name {
            margin-top: 0.8rem;
            color: var(--accent2);
            font-size: 0.9rem;
            min-height: 1.4em;
        }

        /* Error */
        .error-box {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            color: var(--red);
            margin-top: 1.5rem;
        }

        /* Results */
        .results {
            margin-top: 2rem;
        }
        .result-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .result-header .format-badge {
            display: inline-block;
            padding: 0.35rem 1rem;
            background: var(--accent);
            color: #fff;
            font-weight: 700;
            font-size: 0.95rem;
            border-radius: 6px;
            letter-spacing: 0.02em;
        }
        .result-header .packed-badge {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            background: rgba(239, 68, 68, 0.15);
            color: var(--red);
            font-weight: 600;
            font-size: 0.8rem;
            border-radius: 6px;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .result-header .info {
            color: var(--muted);
            font-size: 0.9rem;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.2rem 1.4rem;
        }
        .card h3 {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--muted);
            margin-bottom: 0.8rem;
        }
        .card table {
            width: 100%;
            border-collapse: collapse;
        }
        .card td {
            padding: 0.3rem 0;
            font-size: 0.88rem;
            vertical-align: top;
        }
        .card td:first-child {
            color: var(--muted);
            width: 40%;
            padding-right: 0.5rem;
        }
        .card td:last-child {
            font-weight: 500;
            word-break: break-all;
        }

        /* Detection items */
        .detection-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border);
        }
        .detection-item:last-child { border-bottom: none; }
        .detection-name {
            font-weight: 600;
            font-size: 0.9rem;
        }
        .detection-version {
            color: var(--muted);
            font-size: 0.8rem;
            margin-left: 0.4rem;
        }
        .detection-method {
            color: var(--muted);
            font-size: 0.72rem;
            font-style: italic;
        }
        .conf-bar {
            width: 80px;
            height: 18px;
            background: var(--surface2);
            border-radius: 9px;
            position: relative;
            overflow: hidden;
            flex-shrink: 0;
        }
        .conf-fill {
            height: 100%;
            border-radius: 9px;
            transition: width 0.5s;
        }
        .conf-bar span {
            position: absolute;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.7rem;
            font-weight: 700;
            color: #fff;
            text-shadow: 0 1px 2px rgba(0,0,0,0.5);
        }

        /* Entropy bar */
        .entropy-vis {
            margin-top: 0.5rem;
        }
        .entropy-overall {
            font-size: 1.6rem;
            font-weight: 700;
            line-height: 1;
        }
        .entropy-label {
            font-size: 0.8rem;
            color: var(--muted);
        }
        .entropy-blocks {
            display: flex;
            gap: 1px;
            height: 32px;
            margin-top: 0.8rem;
            border-radius: 4px;
            overflow: hidden;
        }
        .entropy-block {
            flex: 1;
            min-width: 2px;
        }
        .entropy-legend {
            display: flex;
            justify-content: space-between;
            font-size: 0.72rem;
            color: var(--muted);
            margin-top: 0.3rem;
        }

        /* Sections table */
        .sections-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
            margin-top: 0.5rem;
        }
        .sections-table th {
            text-align: left;
            color: var(--muted);
            font-weight: 600;
            padding: 0.4rem 0.5rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .sections-table td {
            padding: 0.35rem 0.5rem;
            border-bottom: 1px solid rgba(46, 51, 72, 0.4);
            font-family: 'Consolas', 'SF Mono', monospace;
            font-size: 0.8rem;
        }
        .flag-r { color: var(--green); }
        .flag-w { color: var(--yellow); }
        .flag-x { color: var(--red); }

        /* JSON toggle */
        .json-toggle {
            margin-top: 1.5rem;
        }
        .json-toggle summary {
            cursor: pointer;
            color: var(--accent2);
            font-size: 0.9rem;
            font-weight: 600;
        }
        .json-output {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 0.5rem;
            overflow-x: auto;
            font-family: 'Consolas', 'SF Mono', 'Fira Code', monospace;
            font-size: 0.82rem;
            line-height: 1.5;
            white-space: pre;
            color: var(--text);
            max-height: 500px;
            overflow-y: auto;
        }

        footer {
            text-align: center;
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-size: 0.82rem;
        }
        footer a {
            color: var(--accent2);
            text-decoration: none;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>DetectItEasy-PHP</h1>
        <p>Universal file type detection &amp; binary analysis</p>
    </header>

    <form method="POST" enctype="multipart/form-data">
        <div class="upload-card" id="drop-zone">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 16V4m0 0L8 8m4-4l4 4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/>
            </svg>
            <h2>Drop a file here or click to browse</h2>
            <p class="hint">PE, ELF, Mach-O, APK, JAR, IPA, ZIP, RAR, PDF, images &mdash; any file</p>
            <input type="file" name="file" id="file-input" required>
            <div id="file-name"></div>
        </div>
        <div style="text-align:center">
            <button type="submit" class="btn">Analyze File</button>
        </div>
    </form>

    <?php if ($error): ?>
        <div class="error-box"><?= esc($error) ?></div>
    <?php endif; ?>

    <?php if ($result && !$result->hasError()): ?>
    <?php $data = $result->toArray(); $meta = $result->getMetadata(); $entropy = $result->getEntropy(); ?>
    <div class="results">
        <div class="result-header">
            <span class="format-badge"><?= esc($result->getFileFormat() ?? 'Unknown') ?></span>
            <?php if ($result->isPacked()): ?>
                <span class="packed-badge">PACKED / PROTECTED</span>
            <?php endif; ?>
            <span class="info">
                <?= esc($uploadedName ?? '') ?> &mdash; <?= formatSize($result->getFileSize()) ?>
                <?php if ($result->getFormatDescription()): ?>
                    &mdash; <?= esc($result->getFormatDescription()) ?>
                <?php endif; ?>
            </span>
        </div>

        <div class="cards">
            <!-- File Info Card -->
            <div class="card">
                <h3>File Information</h3>
                <table>
                    <tr><td>Format</td><td><?= esc($result->getFileFormat() ?? 'Unknown') ?></td></tr>
                    <tr><td>Description</td><td><?= esc($result->getFormatDescription() ?? 'N/A') ?></td></tr>
                    <tr><td>MIME Type</td><td><?= esc($result->getMimeType() ?? 'N/A') ?></td></tr>
                    <tr><td>Size</td><td><?= formatSize($result->getFileSize()) ?> (<?= number_format($result->getFileSize()) ?> bytes)</td></tr>
                    <?php if (isset($meta['machine'])): ?>
                        <tr><td>Architecture</td><td><?= esc((string)$meta['machine']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['subsystem'])): ?>
                        <tr><td>Subsystem</td><td><?= esc((string)$meta['subsystem']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['entry_point'])): ?>
                        <tr><td>Entry Point</td><td><code><?= esc((string)$meta['entry_point']) ?></code></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['linker_version'])): ?>
                        <tr><td>Linker Version</td><td><?= esc((string)$meta['linker_version']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['is_dll'])): ?>
                        <tr><td>DLL</td><td><?= $meta['is_dll'] ? 'Yes' : 'No' ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['timestamp_date'])): ?>
                        <tr><td>Timestamp</td><td><?= esc((string)$meta['timestamp_date']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['elf_type'])): ?>
                        <tr><td>ELF Type</td><td><?= esc((string)$meta['elf_type']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['os_abi'])): ?>
                        <tr><td>OS/ABI</td><td><?= esc((string)$meta['os_abi']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['platform'])): ?>
                        <tr><td>Platform</td><td><?= esc((string)$meta['platform']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['min_os_version'])): ?>
                        <tr><td>Min OS Version</td><td><?= esc((string)$meta['min_os_version']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['cpu_type'])): ?>
                        <tr><td>CPU Type</td><td><?= esc((string)$meta['cpu_type']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['file_type'])): ?>
                        <tr><td>Mach-O Type</td><td><?= esc((string)$meta['file_type']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['uuid'])): ?>
                        <tr><td>UUID</td><td><code style="font-size:0.78rem"><?= esc((string)$meta['uuid']) ?></code></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['stripped'])): ?>
                        <tr><td>Stripped</td><td><?= $meta['stripped'] ? 'Yes' : 'No' ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['linking'])): ?>
                        <tr><td>Linking</td><td><?= esc(ucfirst((string)$meta['linking'])) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['dex_count'])): ?>
                        <tr><td>DEX Files</td><td><?= (int)$meta['dex_count'] ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['native_architectures'])): ?>
                        <tr><td>Native Archs</td><td><?= esc(implode(', ', $meta['native_architectures'])) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['zip_entries'])): ?>
                        <tr><td>Archive Entries</td><td><?= number_format((int)$meta['zip_entries']) ?></td></tr>
                    <?php endif; ?>
                    <?php if (isset($meta['rich_header']) && $meta['rich_header']): ?>
                        <tr><td>Rich Header</td><td>Present (key: <?= esc((string)($meta['rich_header_key'] ?? '?')) ?>)</td></tr>
                    <?php endif; ?>
                </table>
            </div>

            <!-- Detections Card -->
            <?php $detections = $result->getDetections(); if (!empty($detections)): ?>
            <div class="card">
                <h3>Detections</h3>
                <?php foreach ($detections as $category => $items): ?>
                    <?php foreach ($items as $det): ?>
                    <div class="detection-item">
                        <div>
                            <span style="color:var(--muted);font-size:0.72rem;text-transform:uppercase"><?= esc($category) ?></span><br>
                            <span class="detection-name"><?= esc($det['name']) ?></span>
                            <?php if ($det['version'] !== ''): ?>
                                <span class="detection-version"><?= esc($det['version']) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($det['extra']['method'])): ?>
                                <br><span class="detection-method">via <?= esc($det['extra']['method']) ?></span>
                            <?php endif; ?>
                        </div>
                        <?= confidenceBar($det['confidence']) ?>
                    </div>
                    <?php endforeach; ?>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>

            <!-- Entropy Card -->
            <?php if (!empty($entropy)): ?>
            <div class="card">
                <h3>Entropy Analysis</h3>
                <div class="entropy-vis">
                    <span class="entropy-overall" style="color:<?= entropyColor($entropy['overall']) ?>">
                        <?= number_format($entropy['overall'], 4) ?>
                    </span>
                    <span class="entropy-label"> / 8.0 &mdash; <?= esc(str_replace('_', ' ', $entropy['assessment'] ?? '')) ?></span>

                    <?php if (!empty($entropy['blocks'])): ?>
                    <div class="entropy-blocks">
                        <?php foreach ($entropy['blocks'] as $block): ?>
                            <div class="entropy-block" style="background:<?= entropyColor($block) ?>;opacity:<?= max(0.2, $block / 8) ?>" title="<?= $block ?>"></div>
                        <?php endforeach; ?>
                    </div>
                    <div class="entropy-legend">
                        <span>Min: <?= $entropy['min'] ?></span>
                        <span>Block entropy distribution (first <?= count($entropy['blocks']) ?> blocks)</span>
                        <span>Max: <?= $entropy['max'] ?></span>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>
        </div>

        <!-- Sections Table -->
        <?php if (!empty($meta['sections']) && is_array($meta['sections'])): ?>
        <div class="card" style="margin-top:1rem">
            <h3>Sections (<?= count($meta['sections']) ?>)</h3>
            <table class="sections-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Virtual Size</th>
                        <th>Virtual Addr</th>
                        <th>Raw Size</th>
                        <th>Flags</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($meta['sections'] as $sec): ?>
                    <tr>
                        <td><?= esc($sec['name']) ?></td>
                        <td><?= formatSize($sec['virtual_size']) ?></td>
                        <td><?= esc($sec['virtual_address']) ?></td>
                        <td><?= formatSize($sec['raw_size']) ?></td>
                        <td>
                            <?php if ($sec['readable']): ?><span class="flag-r">R</span><?php endif; ?>
                            <?php if ($sec['writable']): ?><span class="flag-w">W</span><?php endif; ?>
                            <?php if ($sec['executable']): ?><span class="flag-x">X</span><?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- Rich Header Entries -->
        <?php if (!empty($meta['rich_header_entries']) && is_array($meta['rich_header_entries'])): ?>
        <div class="card" style="margin-top:1rem">
            <h3>Rich Header Build Tools</h3>
            <table class="sections-table">
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Tool ID</th>
                        <th>Build ID</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($meta['rich_header_entries'] as $entry): ?>
                    <tr>
                        <td><?= esc($entry['tool_name']) ?></td>
                        <td><?= $entry['tool_id'] ?></td>
                        <td><?= $entry['build_id'] ?></td>
                        <td><?= number_format($entry['count']) ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- Imported DLLs -->
        <?php if (!empty($meta['imported_dlls'])): ?>
        <div class="card" style="margin-top:1rem">
            <h3>Imported DLLs</h3>
            <div style="display:flex;flex-wrap:wrap;gap:0.4rem">
                <?php foreach ($meta['imported_dlls'] as $dll): ?>
                    <code style="background:var(--surface2);padding:0.2rem 0.6rem;border-radius:4px;font-size:0.82rem"><?= esc($dll) ?></code>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- JSON Output -->
        <details class="json-toggle">
            <summary>View Raw JSON Output</summary>
            <div class="json-output"><?= esc($result->toJson(JSON_PRETTY_PRINT)) ?></div>
        </details>
    </div>
    <?php endif; ?>

    <footer>
        Powered by <a href="https://github.com/horsicq/Detect-It-Easy">DetectItEasy</a>-PHP
        &mdash; PHP <?= PHP_VERSION ?>
    </footer>
</div>

<script>
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileName = document.getElementById('file-name');

['dragenter', 'dragover'].forEach(e => {
    dropZone.addEventListener(e, ev => { ev.preventDefault(); dropZone.classList.add('dragover'); });
});
['dragleave', 'drop'].forEach(e => {
    dropZone.addEventListener(e, ev => { ev.preventDefault(); dropZone.classList.remove('dragover'); });
});
dropZone.addEventListener('drop', ev => {
    if (ev.dataTransfer.files.length) {
        fileInput.files = ev.dataTransfer.files;
        fileName.textContent = ev.dataTransfer.files[0].name;
    }
});
fileInput.addEventListener('change', () => {
    if (fileInput.files.length) fileName.textContent = fileInput.files[0].name;
});
</script>
</body>
</html>
