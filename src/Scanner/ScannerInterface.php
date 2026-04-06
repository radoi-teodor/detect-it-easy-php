<?php

declare(strict_types=1);

namespace DetectItEasy\Scanner;

use DetectItEasy\Result\AnalysisResult;

interface ScannerInterface
{
    /**
     * Perform a deep scan of the binary data.
     *
     * @param string $data     Raw binary data.
     * @param int    $fileSize Total file size (may differ from strlen($data)).
     * @param AnalysisResult $result Result object to populate.
     */
    public function deepScan(string $data, int $fileSize, AnalysisResult $result): void;
}
