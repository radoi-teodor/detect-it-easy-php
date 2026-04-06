<?php

declare(strict_types=1);

namespace DetectItEasy\Signature;

/**
 * Loads and provides access to signature databases.
 */
class SignatureDatabase
{
    /** @var string */
    private $basePath;

    /** @var array<string, array<int, array<string, mixed>>> */
    private $cache = [];

    public function __construct(string $basePath)
    {
        $this->basePath = rtrim($basePath, '/\\');
    }

    /**
     * Load a signature file by name (without extension).
     *
     * @param string $name e.g. 'magic_bytes', 'pe_compilers'
     * @return array<int, array<string, mixed>>
     */
    public function load(string $name): array
    {
        if (isset($this->cache[$name])) {
            return $this->cache[$name];
        }

        $file = $this->basePath . '/' . $name . '.json';
        if (!is_file($file)) {
            return [];
        }

        $content = file_get_contents($file);
        if ($content === false) {
            return [];
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return [];
        }

        $this->cache[$name] = $data;
        return $data;
    }

    /**
     * Get all signatures for a format and category.
     *
     * @param string $format   e.g. 'pe', 'elf', 'macho'
     * @param string $category e.g. 'compilers', 'packers', 'protectors'
     * @return array<int, array<string, mixed>>
     */
    public function getSignatures(string $format, string $category): array
    {
        return $this->load($format . '_' . $category);
    }

    /**
     * Get magic bytes signatures.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getMagicBytes(): array
    {
        return $this->load('magic_bytes');
    }

    public function getBasePath(): string
    {
        return $this->basePath;
    }
}
