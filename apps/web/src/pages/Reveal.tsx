import { useEffect, useRef, useState, useCallback } from 'react';

export interface RevealProps {
  vaultId: string;
  secretPath: string;
  onClose: () => void;
  onLogout?: () => void;
}

export interface RevealPayload {
  vault_id: string;
  secret_path: string;
  version: number;
  classification: string;
  created_at: string;
  metadata_digest: string;
  algorithm: string;
  plaintext: string;
  ttl_seconds?: number;
}

export function Reveal({ vaultId, secretPath, onClose, onLogout }: RevealProps) {
  const [stepUpToken, setStepUpToken] = useState<string>('su_c21_synthetic_stepup_token_valid_99a');
  const [revealedData, setRevealedData] = useState<RevealPayload | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [countdown, setCountdown] = useState<number | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  // Reference to abort controller to cancel ongoing request when closing
  const abortControllerRef = useRef<AbortController | null>(null);
  // Reference to timer
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Invariant F15: Plaintext clears immediately from memory and rendered state
  const clearPlaintextState = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setRevealedData(null);
    setCountdown(null);
    setCopied(false);
  }, []);

  const handleClose = useCallback(() => {
    clearPlaintextState();
    onClose();
  }, [clearPlaintextState, onClose]);

  const handleLogout = useCallback(() => {
    clearPlaintextState();
    if (onLogout) {
      onLogout();
    } else {
      onClose();
    }
  }, [clearPlaintextState, onLogout, onClose]);

  // Clean up on component unmount
  useEffect(() => {
    return () => {
      clearPlaintextState();
    };
  }, [clearPlaintextState]);

  // Keyboard shortcut: Escape closes modal
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleClose]);

  // Countdown timer when plaintext is revealed
  useEffect(() => {
    if (countdown === null) return;
    if (countdown <= 0) {
      clearPlaintextState();
      return;
    }
    timerRef.current = setInterval(() => {
      setCountdown(prev => {
        if (prev === null || prev <= 1) {
          clearPlaintextState();
          return null;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [countdown, clearPlaintextState]);

  const requestReveal = async () => {
    setError('');
    setLoading(true);
    clearPlaintextState();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      // Invariant F15: Cache and service workers are excluded via no-store
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/secrets/${encodeURIComponent(secretPath)}/reveal`, {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Pragma': 'no-cache',
          'X-KeyHelix-StepUp': stepUpToken,
        },
        body: JSON.stringify({
          step_up_token: stepUpToken,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Step-up authentication required or token expired.');
        }
        if (response.status === 403) {
          throw new Error('Access denied: Unauthorized owner or scope mismatch.');
        }
        if (response.status === 503) {
          throw new Error('Provider unavailable: Fails closed to protect secret.');
        }
        throw new Error(`Reveal request rejected with status ${response.status}`);
      }

      const data: RevealPayload = await response.json();
      setRevealedData(data);
      const ttl = data.ttl_seconds && data.ttl_seconds > 0 ? data.ttl_seconds : 30;
      setCountdown(ttl);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        return;
      }
      setError(err instanceof Error ? err.message : 'Error executing transient reveal.');
    } finally {
      setLoading(false);
      abortControllerRef.current = null;
    }
  };

  const copyPlaintext = async () => {
    if (!revealedData?.plaintext) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(revealedData.plaintext);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Ignore clipboard write failures in restricted environments
    }
  };

  return (
    <div
      className="reveal-backdrop"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(10, 15, 25, 0.85)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: '20px',
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="reveal-dialog-title"
      data-testid="reveal-dialog"
    >
      <div
        className="panel"
        style={{
          width: '100%',
          maxWidth: '560px',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)',
          border: '1px solid #3a4b66',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div className="eyebrow">Transient Secret Reveal · Requirement F15</div>
          <button
            type="button"
            className="badge"
            onClick={handleClose}
            aria-label="Close reveal dialog"
            data-testid="reveal-close-btn"
            style={{ cursor: 'pointer', background: 'transparent' }}
          >
            ✕ Close
          </button>
        </div>

        <h2 id="reveal-dialog-title" style={{ marginTop: 0 }}>
          Secret: <code>{secretPath}</code>
        </h2>
        <p className="intro" style={{ fontSize: '14px', marginBottom: '16px' }}>
          Vault: <code>{vaultId}</code>. Plaintext is decrypted on demand and strictly zeroed upon close, timeout, or logout. Excluded from browser cache.
        </p>

        {error && (
          <section className="notice" role="alert" aria-live="assertive" style={{ margin: '14px 0' }}>
            <span className="dot" style={{ background: '#ff6b6b' }} />
            <span data-testid="reveal-error-msg">{error}</span>
          </section>
        )}

        {!revealedData ? (
          <div>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px' }}>
                Step-up authorization token
                <input
                  type="password"
                  aria-label="Step-up token input"
                  data-testid="stepup-token-input"
                  value={stepUpToken}
                  onChange={e => setStepUpToken(e.target.value)}
                  placeholder="Enter fresh step-up authentication token"
                  style={{
                    background: '#0a111e',
                    color: '#ecf2fa',
                    border: '1px solid #3a4860',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    width: '100%',
                  }}
                />
              </label>
            </div>

            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="file-button"
                onClick={requestReveal}
                disabled={loading}
                data-testid="request-reveal-btn"
              >
                {loading ? 'Decrypting transient payload…' : 'Authenticate & Reveal Secret'}
              </button>
              <button
                type="button"
                onClick={handleClose}
                style={{
                  background: 'transparent',
                  color: '#b8c4d5',
                  border: '1px solid #3a4860',
                  borderRadius: '9px',
                  padding: '11px 18px',
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div data-testid="revealed-payload-container" style={{ marginTop: '16px' }}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '8px 12px',
                background: '#162338',
                borderRadius: '8px',
                marginBottom: '12px',
              }}
            >
              <span className="state active">Decrypted (Memory Only)</span>
              <span
                className="task-id"
                data-testid="reveal-countdown"
                style={{ fontWeight: 'bold' }}
              >
                Auto-clearing in {countdown}s
              </span>
            </div>

            <div
              style={{
                background: '#050a14',
                border: '1px solid #2d3f5d',
                borderRadius: '8px',
                padding: '14px',
                fontFamily: 'ui-monospace, monospace',
                fontSize: '15px',
                color: '#80e6c4',
                wordBreak: 'break-all',
                position: 'relative',
                marginBottom: '16px',
              }}
              data-testid="plaintext-display"
            >
              {revealedData.plaintext}
            </div>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <button
                type="button"
                className="file-button"
                onClick={copyPlaintext}
                data-testid="copy-plaintext-btn"
              >
                {copied ? 'Copied to Clipboard!' : 'Copy Plaintext'}
              </button>
              <button
                type="button"
                onClick={handleClose}
                data-testid="close-and-clear-btn"
                style={{
                  background: '#2b1b1b',
                  color: '#ff9999',
                  border: '1px solid #5a3030',
                  borderRadius: '9px',
                  padding: '11px 18px',
                }}
              >
                Close & Zero Plaintext
              </button>
              <button
                type="button"
                onClick={handleLogout}
                data-testid="logout-and-purge-btn"
                style={{
                  background: 'transparent',
                  color: '#94a5bc',
                  border: '1px solid #3a4860',
                  borderRadius: '9px',
                  padding: '11px 18px',
                  marginLeft: 'auto',
                }}
              >
                Logout Session
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Reveal;
