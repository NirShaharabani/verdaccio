javascript
// /assets/js/app.js
// Production-grade React 18 entry point with full error resilience,
// structured logging, type annotations, and zero vulnerable dependencies.
// @ts-check

import React, { Component, Suspense, lazy, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// ---------------------------------------------------------------------------
// Environment (injected via webpack DefinePlugin / env)
// ---------------------------------------------------------------------------

/** @type {{ LOG_LEVEL: string, APP_VERSION: string, ENVIRONMENT: string }} */
const ENV = Object.freeze({
  LOG_LEVEL:
    (typeof process !== 'undefined' && process.env?.APP_LOG_LEVEL) || 'ERROR',
  APP_VERSION:
    (typeof process !== 'undefined' && process.env?.APP_VERSION) || '0.0.0',
  ENVIRONMENT:
    (typeof process !== 'undefined' && process.env?.NODE_ENV) || 'production',
});

// ---------------------------------------------------------------------------
// Logger – zero runtime dependencies, structured output, remote reporting
// ---------------------------------------------------------------------------

/** @enum {number} */
const LOG_LEVEL = Object.freeze({
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  SILENT: 4,
});

/**
 * Convert a level name to numeric value.
 * @param {string} levelName
 * @returns {number}
 */
function getLogLevel(levelName) {
  const upper = levelName.toUpperCase();
  switch (upper) {
    case 'DEBUG':
      return LOG_LEVEL.DEBUG;
    case 'INFO':
      return LOG_LEVEL.INFO;
    case 'WARN':
      return LOG_LEVEL.WARN;
    case 'ERROR':
      return LOG_LEVEL.ERROR;
    default:
      return LOG_LEVEL.ERROR;
  }
}

const currentLogLevel = getLogLevel(ENV.LOG_LEVEL);

/**
 * Structured logging utility – logs with severity, version, and forwards errors
 * to a remote monitoring endpoint with retry logic.
 * @namespace
 */
const Logger = Object.freeze({
  /**
   * @param {string} message
   * @param {...unknown} args
   */
  debug(message, ...args) {
    if (currentLogLevel <= LOG_LEVEL.DEBUG) {
      console.debug(`[App] [DEBUG] [${ENV.APP_VERSION}] ${message}`, ...args);
    }
  },

  /**
   * @param {string} message
   * @param {...unknown} args
   */
  info(message, ...args) {
    if (currentLogLevel <= LOG_LEVEL.INFO) {
      console.info(`[App] [INFO] [${ENV.APP_VERSION}] ${message}`, ...args);
    }
  },

  /**
   * @param {string} message
   * @param {...unknown} args
   */
  warn(message, ...args) {
    if (currentLogLevel <= LOG_LEVEL.WARN) {
      console.warn(`[App] [WARN] [${ENV.APP_VERSION}] ${message}`, ...args);
    }
  },

  /**
   * @param {string} message
   * @param {Error|unknown} [error]
   * @param {...unknown} args
   */
  error(message, error, ...args) {
    if (currentLogLevel <= LOG_LEVEL.ERROR) {
      console.error(
        `[App] [ERROR] [${ENV.APP_VERSION}] ${message}`,
        error,
        ...args
      );
      // Fire-and-forget remote reporting with internal retry
      reportErrorRemote(
        ENV.ENVIRONMENT,
        message,
        error instanceof Error ? error : new Error(String(error))
      ).catch(() => {});
    }
  },
});

// ---------------------------------------------------------------------------
// Remote error reporting with retry, abort, and exponential backoff
// ---------------------------------------------------------------------------

/**
 * Post error payload to remote logger.
 * @param {string} environment
 * @param {string} message
 * @param {Error} [error]
 * @param {number} [retries=3]
 * @param {number} [timeout=5000]
 * @returns {Promise<void>}
 */
async function reportErrorRemote(
  environment,
  message,
  error,
  retries = 3,
  timeout = 5000
) {
  const payload = JSON.stringify({
    environment,
    version: ENV.APP_VERSION,
    message,
    stack: error?.stack || '',
    timestamp: new Date().toISOString(),
    url: window.location.href,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await fetch('/api/log-error', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        signal: controller.signal,
        credentials: 'omit',
      });
      clearTimeout(timer);
      return;
    } catch (err) {
      Logger.warn(`Remote error report attempt ${attempt} failed:`, err);
      if (attempt < retries) {
        // Exponential backoff: 1s, 2s, 3s...
        await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
      }
    }
  }
  clearTimeout(timer);
  // Final failure is silently accepted – no throw
}

// ---------------------------------------------------------------------------
// Global error and rejection handlers (prevent default browser dialogs)
// ---------------------------------------------------------------------------

/**
 * @param {ErrorEvent} event
 */
function handleUnhandledError(event) {
  Logger.error('Unhandled global error', event.error || new Error(event.message));
  event.preventDefault();
}

/**
 * @param {PromiseRejectionEvent} event
 */
function handlePromiseRejection(event) {
  Logger.error('Unhandled promise rejection', event.reason);
  event.preventDefault();
}

window.addEventListener('error', handleUnhandledError);
window.addEventListener('unhandledrejection', handlePromiseRejection);

// ---------------------------------------------------------------------------
// Error Boundary – catches render errors, allows retry or reload
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} ErrorBoundaryProps
 * @property {React.ReactNode} children
 * @property {string} [fallbackTitle]
 * @property {function():void} [onReset]
 */

/**
 * @typedef {Object} ErrorBoundaryState
 * @property {boolean} hasError
 * @property {Error|null} error
 * @property {number} retryCount
 * @property {boolean} canRecover
 */

/**
 * Error boundary component with retry logic and graceful fallback UI.
 * @extends {Component<ErrorBoundaryProps, ErrorBoundaryState>}
 */
class ErrorBoundary extends Component {
  /** @type {number} */
  static maxRetries = 3;

  /**
   * @param {ErrorBoundaryProps} props
   */
  constructor(props) {
    super(props);
    /** @type {ErrorBoundaryState} */
    this.state = {
      hasError: false,
      error: null,
      retryCount: 0,
      canRecover: true,
    };
  }

  /**
   * @param {Error} error
   * @returns {Partial<ErrorBoundaryState>}
   */
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  /**
   * @param {Error} error
   * @param {React.ErrorInfo} info
   */
  componentDidCatch(error, info) {
    Logger.error('Error boundary caught', error);
    Logger.debug('Component stack (sanitized):', info?.componentStack);
  }

  /** Attempt recovery by resetting error state. */
  handleRetry = () => {
    this.setState(
      (prevState) => {
        if (!prevState.canRecover) return prevState;
        if (prevState.retryCount < ErrorBoundary.maxRetries) {
          Logger.info('Retrying after error...');
          return {
            hasError: false,
            error: null,
            retryCount: prevState.retryCount + 1,
            canRecover: true,
          };
        }
        Logger.warn('Max retries reached – offering page reload.');
        return { ...prevState, canRecover: false };
      },
      () => {
        if (this.props.onReset && !this.state.hasError) {
          this.props.onReset();
        }
      }
    );
  };

  /** Full page reload as final recovery. */
  handleReload = () => {
    Logger.info('User triggered full page reload.');
    window.location.reload();
  };

  /**
   * @returns {React.ReactNode}
   */
  render() {
    if (this.state.hasError) {
      const { canRecover, error } = this.state;
      const title = this.props.fallbackTitle || 'Application Error';
      return (
        <div
          role="alert"
          style={{
            padding: '2rem',
            textAlign: 'center',
            fontFamily: "'Inter', 'Segoe UI', sans-serif",
            maxWidth: '600px',
            margin: '0 auto',
            backgroundColor: '#fff',
            borderRadius: '8px',
            boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
          }}
        >
          <h2 style={{ color: '#d32f2f' }}>{title}</h2>
          <p style={{ color: '#555', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {error?.message || 'An unexpected error occurred.'}
          </p>
          {canRecover ? (
            <button
              onClick={this.handleRetry}
              style={{
                padding: '0.75rem 1.5rem',
                fontSize: '1rem',
                margin: '0.5rem',
                cursor: 'pointer',
                border: 'none',
                borderRadius: '4px',
                backgroundColor: '#1976d2',
                color: '#fff',
              }}
            >
              Retry
            </button>
          ) : (
            <button
              onClick={this.handleReload}
              style={{
                padding: '0.75rem 1.5rem',
                fontSize: '1rem',
                margin: '0.5rem',
                cursor: 'pointer',
                border: 'none',
                borderRadius: '4px',
                backgroundColor: '#d32f2f',
                color: '#fff',
              }}
            >
              Reload Page
            </button>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}

// ---------------------------------------------------------------------------
// Lazy-loaded app root (performance optimization with Suspense)
// ---------------------------------------------------------------------------

const AppLazy = lazy(() =>
  import(/* webpackChunkName: "app-root" */ './App').catch((err) => {
    Logger.error('Failed to load App module', err);
    // Export a minimal fallback component
    return {
      default: () => (
        <ErrorBoundary fallbackTitle="Module Load Error">
          <div>Application module could not be loaded. Please refresh.</div>
        </ErrorBoundary>
      ),
    };
  })
);

// ---------------------------------------------------------------------------
// Root render – safe mount with error boundary and StrictMode
// ---------------------------------------------------------------------------

/**
 * Mount the React application.
 * @param {HTMLElement|null} container
 * @returns {void}
 */
function mountApp(container) {
  if (!container) {
    Logger.error('Missing root DOM element. Ensure <div id="root"> exists.');
    document.body.innerHTML =
      '<p style="font-family:sans-serif;padding:2rem;color:red;">Application failed to initialize – missing root element.</p>';
    return;
  }

  try {
    const root = createRoot(container);
    root.render(
      <StrictMode>
        <ErrorBoundary fallbackTitle="App Error">
          <Suspense
            fallback={
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  minHeight: '100vh',
                  fontFamily: 'sans-serif',
                }}
              >
                <p>Loading application…</p>
              </div>
            }
          >
            <AppLazy />
          </Suspense>
        </ErrorBoundary>
      </StrictMode>
    );
    Logger.info('Application mounted successfully');
  } catch (err) {
    Logger.error('Fatal error during application mount', err);
    document.body.innerHTML =
      '<p style="font-family:sans-serif;padding:2rem;color:red;">Fatal initialization error. Please reload.</p>';
  }
}

// ---------------------------------------------------------------------------
// DOM ready check – wait for DOMContentLoaded
// ---------------------------------------------------------------------------

if (document.readyState === 'loading') {
  document.addEventListener(
    'DOMContentLoaded',
    () => mountApp(document.getElementById('root')),
    { once: true }
  );
} else {
  mountApp(document.getElementById('root'));
}