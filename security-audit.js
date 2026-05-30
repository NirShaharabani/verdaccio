javascript
/**
 * @fileoverview Production-grade client-side Subresource Integrity (SRI) auditor.
 * Replaces vulnerable node-forge with native Web Crypto API.
 * Monitors the integrity of loaded scripts and stylesheets by recomputing their
 * hashes and comparing against expected values. Designed for modern browsers.
 * Fully CSP-compliant.
 * @version 2.1.0
 * @module SecurityAudit
 * @author AIGON Enterprise
 * @license MIT
 */

(function (global) {
  'use strict';

  // =========================================================================
  // Polyfill check (minimal)
  // =========================================================================
  if (
    typeof global.crypto === 'undefined' ||
    typeof global.crypto.subtle === 'undefined'
  ) {
    // Do not throw – gracefully disable if not available
    console.warn('[SecurityAudit] Web Crypto API not available. Security auditing disabled.');
    return;
  }

  // =========================================================================
  // Constants (immutable)
  // =========================================================================

  /** @const {ReadonlyArray<string>} Supported hash algorithms (SRI standard). */
  const SUPPORTED_ALGORITHMS = Object.freeze(['sha256', 'sha384', 'sha512']);

  /** @const {Readonly<Object<string, string>>} Algorithm name → Web Crypto algorithm identifier. */
  const ALGORITHM_MAP = Object.freeze({
    sha256: 'SHA-256',
    sha384: 'SHA-384',
    sha512: 'SHA-512',
  });

  /** @const {RegExp} Base64 alphabet (RFC 4648, no padding required). */
  const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

  /** @const {string} Default logger prefix. */
  const DEFAULT_LOG_PREFIX = '[SecurityAudit]';

  /** @const {number} Maximum cache size to prevent memory leak (entries). */
  const MAX_CACHE_SIZE = 100;

  /** @const {number} Default initial audit delay (ms). */
  const DEFAULT_INIT_DELAY = 100;

  /** @const {number} Maximum number of audit retries per resource. */
  const MAX_RETRIES = 3;

  /** @const {number} Retry backoff multiplier (exponential). */
  const RETRY_BACKOFF = 1.5;

  /** @const {number} Maximum fetch size in bytes (10 MB). */
  const MAX_FETCH_SIZE = 10 * 1024 * 1024;

  /** @const {number} Cache entry TTL in milliseconds (5 minutes). */
  const CACHE_TTL = 5 * 60 * 1000;

  // =========================================================================
  // Types (JSDoc)
  // =========================================================================

  /**
   * @typedef {Object} IntegrityExpectation
   * @property {string} algorithm - One of 'sha256', 'sha384', 'sha512'.
   * @property {string} base64Hash - Base64-encoded hash (unpadded).
   */

  /**
   * @typedef {Object} SecurityAuditConfig
   * @property {string} [logPrefix='[SecurityAudit]'] - Prefix for log messages.
   * @property {boolean} [enabled=true] - Enable/disable auditing.
   * @property {boolean} [autoRegisterFromDOM=true] - Automatically register elements with `integrity` attribute.
   * @property {number} [initDelay=100] - Delay (ms) before initial audit after `init()`.
   * @property {boolean} [observeMutations=true] - Watch DOM for new scripts/styles.
   * @property {Function} [onFailure] - Callback when an audit fails (receives AuditResult).
   * @property {Function} [onSuccess] - Callback when an audit passes.
   * @property {Function} [logFn=null] - Custom logging function (signature: (level, ...args) => void).
   *                                     If null, uses console.warn/error/info.
   */

  /**
   * @typedef {Object} AuditCheck
   * @property {string} algorithm - Algorithm used.
   * @property {string} expected - Expected base64 hash.
   * @property {string|null} computed - Computed base64 hash (null if error).
   * @property {boolean} match - True if computed matches expected.
   */

  /**
   * @typedef {Object} AuditResult
   * @property {string} url - Asset URL.
   * @property {boolean} passed - True if all expectations matched.
   * @property {Array<AuditCheck>} checks - Per-algorithm results.
   * @property {string|null} error - Error message if retrieval or computation failed.
   */

  /**
   * @typedef {Object} CacheEntry
   * @property {ArrayBuffer} data - The resource content.
   * @property {number} timestamp - When this entry was cached.
   */

  // =========================================================================
  // Utility Functions (pure, testable)
  // =========================================================================

  /**
   * Safely retrieves a logger object with warn, error, info methods.
   * @param {SecurityAuditConfig['logFn']|undefined} [customLogFn] - Optional custom log function.
   * @returns {{ warn: Function, error: Function, info: Function }} Logger object.
   */
  function getLogger(customLogFn) {
    if (typeof customLogFn === 'function') {
      return {
        warn: (...args) => customLogFn('warn', ...args),
        error: (...args) => customLogFn('error', ...args),
        info: (...args) => customLogFn('info', ...args),
      };
    }

    // Fallback to console methods
    return {
      warn: (...args) => console.warn(...args),
      error: (...args) => console.error(...args),
      info: (...args) => console.info(...args),
    };
  }

  /**
   * Parses an SRI integrity string into an array of expectations.
   * Logs warnings for malformed entries.
   * @param {string} integrity - The integrity attribute value.
   * @param {object} [options] - Options.
   * @param {string} [options.logPrefix=DEFAULT_LOG_PREFIX] - Log prefix.
   * @param {Function} [options.logWarn] - Warning logger (defaults to console.warn).
   * @returns {Array<IntegrityExpectation>} Parsed expectations. Empty array on invalid input.
   */
  function parseIntegrity(integrity, options = {}) {
    const logPrefix = options.logPrefix || DEFAULT_LOG_PREFIX;
    const logWarn = options.logWarn || console.warn;

    if (typeof integrity !== 'string' || integrity.trim().length === 0) {
      return [];
    }

    const pieces = integrity
      .trim()
      .split(/\s+/)
      .filter(Boolean);

    /** @type {Array<IntegrityExpectation>} */
    const results = [];

    for (const piece of pieces) {
      const dashIndex = piece.indexOf('-');
      if (dashIndex === -1) {
        logWarn(`${logPrefix} Invalid SRI piece (missing dash): "${piece}"`);
        continue;
      }

      const algorithm = piece.slice(0, dashIndex).toLowerCase();
      const base64Hash = piece.slice(dashIndex + 1);

      if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
        logWarn(`${logPrefix} Unsupported hash algorithm: "${algorithm}". Supported: ${SUPPORTED_ALGORITHMS.join(', ')}`);
        continue;
      }

      if (!BASE64_REGEX.test(base64Hash)) {
        logWarn(`${logPrefix} Invalid Base64 hash for "${algorithm}": "${base64Hash}"`);
        continue;
      }

      results.push({ algorithm, base64Hash });
    }

    return results;
  }

  /**
   * Computes a digest of the given data using Web Crypto API.
   * @param {string} algorithm - Web Crypto algorithm (e.g., 'SHA-256').
   * @param {ArrayBuffer|Uint8Array} data - Data to hash.
   * @returns {Promise<ArrayBuffer>} Digest as ArrayBuffer.
   * @throws {Error} If crypto.subtle is unavailable or algorithm is invalid.
   * @throws {TypeError} If data type is invalid.
   */
  async function computeDigest(algorithm, data) {
    if (!crypto?.subtle) {
      throw new Error('Web Crypto API (crypto.subtle) is not available.');
    }

    if (typeof algorithm !== 'string' || !Object.values(ALGORITHM_MAP).includes(algorithm)) {
      throw new Error(`Unsupported or invalid digest algorithm: "${algorithm}". Supported: ${Object.values(ALGORITHM_MAP).join(', ')}`);
    }

    if (!(data instanceof ArrayBuffer || data instanceof Uint8Array)) {
      throw new TypeError('Invalid data type; expected ArrayBuffer or Uint8Array.');
    }

    return crypto.subtle.digest(algorithm, data);
  }

  /**
   * Converts an ArrayBuffer to unpadded Base64 string.
   * Uses `TextDecoder` + `btoa` for better performance on large buffers.
   * @param {ArrayBuffer} buffer - The buffer.
   * @returns {string} Unpadded Base64 string.
   * @throws {TypeError} If buffer is not an ArrayBuffer.
   */
  function arrayBufferToBase64(buffer) {
    if (!(buffer instanceof ArrayBuffer)) {
      throw new TypeError('Invalid input: expected an ArrayBuffer.');
    }

    // Use TextDecoder for efficient binary string conversion
    const decoder = new TextDecoder('latin1'); // latin1 maps bytes 0–255 to same code points
    const binaryString = decoder.decode(buffer);
    return btoa(binaryString).replace(/=+$/, '');
  }

  /**
   * Validates that a resource URL is acceptable for fetching.
   * Skips blob:, data:, javascript:, about:, etc.
   * @param {string} url - The resource URL.
   * @returns {boolean} True if the URL is fetchable.
   */
  function isFetchableURL(url) {
    if (typeof url !== 'string' || url.length === 0) {
      return false;
    }
    // Allow http, https, and same-origin relative URLs
    return !/^(blob|data|javascript|about|file):/i.test(url);
  }

  // =========================================================================
  // Resource Cache (with TTL and size limit)
  // =========================================================================

  /**
   * @class ResourceCache
   * @description In-memory cache for fetched resources with LRU-like eviction and TTL.
   */
  class ResourceCache {
    constructor() {
      /** @type {Map<string, CacheEntry>} */
      this._cache = new Map();
    }

    /**
     * Retrieves a cached entry if it exists and is not expired.
     * @param {string} url - The resource URL.
     * @returns {ArrayBuffer|null} The cached data, or null.
     */
    get(url) {
      const entry = this._cache.get(url);
      if (!entry) return null;
      if (Date.now() - entry.timestamp > CACHE_TTL) {
        this._cache.delete(url);
        return null;
      }
      // Move to end (LRU touch)
      this._cache.delete(url);
      this._cache.set(url, entry);
      return entry.data;
    }

    /**
     * Stores data in the cache. Evicts oldest if over limit.
     * @param {string} url - The resource URL.
     * @param {ArrayBuffer} data - The resource data.
     * @returns {void}
     */
    set(url, data) {
      if (this._cache.size >= MAX_CACHE_SIZE) {
        // Delete oldest (first in insertion order)
        const oldestKey = this._cache.keys().next().value;
        if (oldestKey !== undefined) {
          this._cache.delete(oldestKey);
        }
      }
      this._cache.set(url, { data, timestamp: Date.now() });
    }
  }

  // =========================================================================
  // Core Audit Functionality
  // =========================================================================

  /**
   * Fetches a resource with retry and exponential backoff.
   * @param {string} url - The absolute URL.
   * @param {number} [retryCount=0] - Internal retry counter.
   * @returns {Promise<ArrayBuffer>} The resource content.
   * @throws {Error} If fetch fails after retries or exceeds size limit.
   */
  async function fetchResource(url, retryCount = 0) {
    try {
      const response = await fetch(url, { cache: 'force-cache', signal: AbortSignal.timeout(15000) });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const contentLength = response.headers.get('Content-Length');
      if (contentLength && parseInt(contentLength, 10) > MAX_FETCH_SIZE) {
        throw new Error(`Resource exceeds maximum size (${MAX_FETCH_SIZE} bytes)`);
      }
      const buffer = await response.arrayBuffer();
      if (buffer.byteLength > MAX_FETCH_SIZE) {
        throw new Error(`Resource exceeds maximum size (${MAX_FETCH_SIZE} bytes after download)`);
      }
      return buffer;
    } catch (error) {
      if (retryCount < MAX_RETRIES) {
        const delay = Math.min(1000 * Math.pow(RETRY_BACKOFF, retryCount), 5000);
        await new Promise((resolve) => setTimeout(resolve, delay));
        return fetchResource(url, retryCount + 1);
      }
      throw error;
    }
  }

  /**
   * Performs SRI audit on a single resource.
   * @param {string} url - Resource URL.
   * @param {string} expectedIntegrity - The `integrity` attribute value.
   * @param {ResourceCache} cache - The shared cache instance.
   * @param {object} logger - Logger with warn/error/info.
   * @param {string} logPrefix - Log prefix.
   * @returns {Promise<AuditResult>} The audit result.
   */
  async function auditResource(url, expectedIntegrity, cache, logger, logPrefix) {
    // Validate URL
    if (!isFetchableURL(url)) {
      return {
        url,
        passed: false,
        checks: [],
        error: `Unfetchable URL: ${url}`,
      };
    }

    // Parse expected integrity
    const expectations = parseIntegrity(expectedIntegrity, { logPrefix, logWarn: logger.warn });
    if (expectations.length === 0) {
      return {
        url,
        passed: false,
        checks: [],
        error: 'No valid integrity expectations found.',
      };
    }

    // Fetch or retrieve from cache
    let data;
    const cached = cache.get(url);
    if (cached) {
      data = cached;
    } else {
      try {
        data = await fetchResource(url);
        cache.set(url, data);
      } catch (error) {
        logger.error(`${logPrefix} Fetch failed for "${url}": ${error.message}`);
        return {
          url,
          passed: false,
          checks: [],
          error: error.message,
        };
      }
    }

    // Compute hashes
    const checks = [];
    let passed = true;
    for (const expectation of expectations) {
      try {
        const algorithmName = ALGORITHM_MAP[expectation.algorithm];
        const digest = await computeDigest(algorithmName, data);
        const computedHash = arrayBufferToBase64(digest);
        const match = computedHash === expectation.base64Hash;
        checks.push({
          algorithm: expectation.algorithm,
          expected: expectation.base64Hash,
          computed: computedHash,
          match,
        });
        if (!match) passed = false;
      } catch (error) {
        logger.error(`${logPrefix} Hash computation error for "${url}" (${expectation.algorithm}): ${error.message}`);
        checks.push({
          algorithm: expectation.algorithm,
          expected: expectation.base64Hash,
          computed: null,
          match: false,
        });
        passed = false;
      }
    }

    return { url, passed, checks, error: null };
  }

  // =========================================================================
  // SecurityAudit Class
  // =========================================================================

  /**
   * Main auditor class for monitoring resource integrity.
   */
  class SecurityAudit {
    /**
     * @param {SecurityAuditConfig} [config] - Configuration options.
     */
    constructor(config = {}) {
      /** @type {SecurityAuditConfig} */
      this._config = {
        logPrefix: config.logPrefix || DEFAULT_LOG_PREFIX,
        enabled: config.enabled !== false,
        autoRegisterFromDOM: config.autoRegisterFromDOM !== false,
        initDelay: config.initDelay || DEFAULT_INIT_DELAY,
        observeMutations: config.observeMutations !== false,
        onFailure: config.onFailure || null,
        onSuccess: config.onSuccess || null,
        logFn: config.logFn || null,
      };

      /** @type {ResourceCache} */
      this._cache = new ResourceCache();

      /** @type {object} */
      this._logger = getLogger(this._config.logFn);

      /** @type {Array<{element: Element, url: string, integrity: string}>} */
      this._registrations = [];

      /** @type {MutationObserver|null} */
      this._observer = null;

      /** @type {Promise<void>} */
      this._ready = Promise.resolve();
    }

    /**
     * Initializes the auditor: registers existing elements and starts mutation observer.
     * @returns {void}
     */
    init() {
      if (!this._config.enabled) {
        this._logger.info(`${this._config.logPrefix} Auditor is disabled.`);
        return;
      }

      this._logger.info(`${this._config.logPrefix} Initializing...`);

      if (this._config.autoRegisterFromDOM) {
        this._registerExistingElements();
      }

      if (this._config.observeMutations) {
        this._startMutationObserver();
      }

      // Schedule initial audit
      setTimeout(() => {
        this._runFullAudit().catch((error) => {
          this._logger.error(`${this._config.logPrefix} Initial audit failed: ${error.message}`);
        });
      }, this._config.initDelay);
    }

    /**
     * Registers a specific element for integrity monitoring.
     * @param {HTMLElement} element - The element (script or link[rel=stylesheet]).
     * @param {string} [url] - Override URL (defaults to element.src or element.href).
     * @returns {void}
     * @throws {TypeError} If element is invalid.
     */
    register(element, url) {
      if (!element || !(element instanceof HTMLElement)) {
        throw new TypeError('register() expects an HTMLElement.');
      }

      const integrity = element.getAttribute('integrity');
      if (!integrity) {
        this._logger.warn(`${this._config.logPrefix} Element has no integrity attribute, skipping registration.`);
        return;
      }

      const actualUrl = url || element.src || element.href;
      if (!actualUrl) {
        this._logger.warn(`${this._config.logPrefix} Element has no src/href, skipping registration.`);
        return;
      }

      // Avoid duplicate registrations
      if (this._registrations.some((r) => r.element === element)) {
        return;
      }

      this._registrations.push({ element, url: actualUrl, integrity });
      this._logger.info(`${this._config.logPrefix} Registered "${actualUrl}" for integrity audit.`);

      // Immediately audit this resource
      this._auditSingle(actualUrl, integrity).catch((error) => {
        this._logger.error(`${this._config.logPrefix} Audit error for "${actualUrl}": ${error.message}`);
      });
    }

    /**
     * Audits all registered resources.
     * @returns {Promise<Array<AuditResult>>} Array of audit results.
     */
    async auditAll() {
      const results = [];
      for (const reg of this._registrations) {
        try {
          const result = await this._auditSingle(reg.url, reg.integrity);
          results.push(result);
        } catch (error) {
          results.push({
            url: reg.url,
            passed: false,
            checks: [],
            error: error.message,
          });
        }
      }
      return results;
    }

    /**
     * Destroys the auditor: stops observer, clears cache and registrations.
     * @returns {void}
     */
    destroy() {
      if (this._observer) {
        this._observer.disconnect();
        this._observer = null;
      }
      this._registrations = [];
      this._cache = new ResourceCache();
      this._logger.info(`${this._config.logPrefix} Auditor destroyed.`);
    }

    // --- Private Methods ---

    /**
     * Registers all existing script and link elements with integrity attributes.
     * @private
     * @returns {void}
     */
    _registerExistingElements() {
      const elements = document.querySelectorAll(
        'script[integrity], link[rel="stylesheet"][integrity]'
      );
      for (const el of elements) {
        if (el instanceof HTMLElement) {
          this.register(el);
        }
      }
    }

    /**
     * Starts a MutationObserver to watch for new script/link elements.
     * @private
     * @returns {void}
     */
    _startMutationObserver() {
      if (typeof MutationObserver === 'undefined') {
        this._logger.warn(`${this._config.logPrefix} MutationObserver not supported.`);
        return;
      }

      this._observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          if (mutation.type === 'childList') {
            for (const node of mutation.addedNodes) {
              if (node instanceof HTMLElement) {
                if (node.tagName === 'SCRIPT' && node.getAttribute('integrity')) {
                  this.register(node);
                } else if (
                  node.tagName === 'LINK' &&
                  node.getAttribute('rel') === 'stylesheet' &&
                  node.getAttribute('integrity')
                ) {
                  this.register(node);
                }
              }
            }
          }
        }
      });

      this._observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });
    }

    /**
     * Runs a full audit of all currently registered resources.
     * @private
     * @returns {Promise<void>}
     */
    async _runFullAudit() {
      const results = await this.auditAll();
      const failures = results.filter((r) => !r.passed && !r.error);
      if (failures.length > 0) {
        this._logger.warn(`${this._config.logPrefix} ${failures.length} integrity failures detected.`);
        if (typeof this._config.onFailure === 'function') {
          for (const result of failures) {
            try {
              this._config.onFailure(result);
            } catch (cbError) {
              this._logger.error(`${this._config.logPrefix} Failure callback error: ${cbError.message}`);
            }
          }
        }
      } else {
        this._logger.info(`${this._config.logPrefix} All registered resources passed integrity check.`);
        if (typeof this._config.onSuccess === 'function') {
          try {
            this._config.onSuccess(results);
          } catch (cbError) {
            this._logger.error(`${this._config.logPrefix} Success callback error: ${cbError.message}`);
          }
        }
      }
    }

    /**
     * Audits a single resource and handles callbacks.
     * @private
     * @param {string} url - Resource URL.
     * @param {string} integrity - Integrity attribute value.
     * @returns {Promise<AuditResult>} The audit result.
     */
    async _auditSingle(url, integrity) {
      const result = await auditResource(url, integrity, this._cache, this._logger, this._config.logPrefix);
      if (!result.passed && typeof this._config.onFailure === 'function') {
        try {
          this._config.onFailure(result);
        } catch (error) {
          this._logger.error(`${this._config.logPrefix} Failure callback error: ${error.message}`);
        }
      } else if (result.passed && typeof this._config.onSuccess === 'function') {
        try {
          this._config.onSuccess(result);
        } catch (error) {
          this._logger.error(`${this._config.logPrefix} Success callback error: ${error.message}`);
        }
      }
      return result;
    }
  }

  // =========================================================================
  // Public API
  // =========================================================================

  /**
   * Factory function to create and initialize a SecurityAudit instance.
   * @param {SecurityAuditConfig} [config] - Configuration options.
   * @returns {SecurityAudit} The created instance.
   */
  function createSecurityAudit(config) {
    const auditor = new SecurityAudit(config);
    auditor.init();
    return auditor;
  }

  // =========================================================================
  // Export
  // =========================================================================

  // Support CommonJS, AMD, and global browser export
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecurityAudit, createSecurityAudit, parseIntegrity };
  } else if (typeof define === 'function' && define.amd) {
    define([], function () {
      return { SecurityAudit, createSecurityAudit, parseIntegrity };
    });
  } else {
    global.SecurityAudit = SecurityAudit;
    global.createSecurityAudit = createSecurityAudit;
    global.parseIntegrity = parseIntegrity;
  }
})(typeof window !== 'undefined' ? window : global);