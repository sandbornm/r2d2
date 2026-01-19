/**
 * Simple result caching utilities for frontend performance.
 * Caches analysis results to avoid re-fetching when switching between sessions.
 */

const CACHE_PREFIX = 'r2d2-cache-';
const MAX_CACHE_SIZE = 10; // Max number of sessions to cache
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes TTL

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

interface CacheIndex {
  keys: string[];
  lastUpdated: number;
}

/**
 * Get the cache index (list of cached keys)
 */
function getCacheIndex(): CacheIndex {
  try {
    const indexStr = sessionStorage.getItem(`${CACHE_PREFIX}index`);
    if (indexStr) {
      return JSON.parse(indexStr);
    }
  } catch {
    // Ignore parse errors
  }
  return { keys: [], lastUpdated: Date.now() };
}

/**
 * Update the cache index
 */
function setCacheIndex(index: CacheIndex): void {
  try {
    sessionStorage.setItem(`${CACHE_PREFIX}index`, JSON.stringify(index));
  } catch {
    // Ignore storage errors
  }
}

/**
 * Evict oldest entries if cache is full
 */
function evictIfNeeded(index: CacheIndex): void {
  while (index.keys.length >= MAX_CACHE_SIZE) {
    const oldestKey = index.keys.shift();
    if (oldestKey) {
      sessionStorage.removeItem(`${CACHE_PREFIX}${oldestKey}`);
    }
  }
}

/**
 * Get a cached value
 */
export function getFromCache<T>(key: string): T | null {
  try {
    const entryStr = sessionStorage.getItem(`${CACHE_PREFIX}${key}`);
    if (!entryStr) return null;

    const entry: CacheEntry<T> = JSON.parse(entryStr);

    // Check TTL
    if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
      sessionStorage.removeItem(`${CACHE_PREFIX}${key}`);
      return null;
    }

    return entry.data;
  } catch {
    return null;
  }
}

/**
 * Set a cached value
 */
export function setInCache<T>(key: string, data: T): void {
  try {
    const index = getCacheIndex();

    // Remove key if it exists (to move it to end)
    const existingIndex = index.keys.indexOf(key);
    if (existingIndex >= 0) {
      index.keys.splice(existingIndex, 1);
    }

    // Evict oldest if needed
    evictIfNeeded(index);

    // Add new entry
    const entry: CacheEntry<T> = {
      data,
      timestamp: Date.now(),
    };

    sessionStorage.setItem(`${CACHE_PREFIX}${key}`, JSON.stringify(entry));
    index.keys.push(key);
    index.lastUpdated = Date.now();
    setCacheIndex(index);
  } catch {
    // Ignore storage errors (quota exceeded, etc.)
  }
}

/**
 * Remove a cached value
 */
export function removeFromCache(key: string): void {
  try {
    sessionStorage.removeItem(`${CACHE_PREFIX}${key}`);
    const index = getCacheIndex();
    const i = index.keys.indexOf(key);
    if (i >= 0) {
      index.keys.splice(i, 1);
      setCacheIndex(index);
    }
  } catch {
    // Ignore errors
  }
}

/**
 * Clear all cached values
 */
export function clearCache(): void {
  try {
    const index = getCacheIndex();
    for (const key of index.keys) {
      sessionStorage.removeItem(`${CACHE_PREFIX}${key}`);
    }
    sessionStorage.removeItem(`${CACHE_PREFIX}index`);
  } catch {
    // Ignore errors
  }
}

/**
 * Cache key generators
 */
export const CacheKeys = {
  analysisResult: (sessionId: string) => `analysis-${sessionId}`,
  sessionMessages: (sessionId: string) => `messages-${sessionId}`,
  functionNames: (sessionId: string) => `funcnames-${sessionId}`,
  annotations: (sessionId: string) => `annotations-${sessionId}`,
};
