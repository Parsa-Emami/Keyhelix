import { useCallback, useEffect, useRef, useState } from 'react';

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
  plaintext_encoding?: string;
  no_store?: boolean;
  ttl_seconds?: number;
}

interface StepUpState {
  action: string;
  resource: string;
  expires_at: string;
}

const pendingKey = 'keyhelix.pendingReveal';

function decodePlaintext(payload: RevealPayload): string {
  if (payload.plaintext_encoding !== 'base64') return payload.plaintext;
  try {
    const bytes = Uint8Array.from(atob(payload.plaintext), character => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

export function Reveal({ vaultId, secretPath, onClose, onLogout }: RevealProps) {
  const [revealedData, setRevealedData] = useState<RevealPayload | null>(null);
  const [plaintext, setPlaintext] = useState('');
  const [elevated, setElevated] = useState<boolean | null>(null);
  const [authorizeUrl, setAuthorizeUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [countdown, setCountdown] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  const abortControllerRef = useRef<AbortController | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

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
    setPlaintext('');
    setCountdown(null);
    setCopied(false);
  }, []);

  const handleClose = useCallback(() => {
    clearPlaintextState();
    onClose();
  }, [clearPlaintextState, onClose]);

  const handleLogout = useCallback(() => {
    clearPlaintextState();
    if (onLogout) onLogout();
    else onClose();
  }, [clearPlaintextState, onLogout, onClose]);

  useEffect(() => () => clearPlaintextState(), [clearPlaintextState]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') handleClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleClose]);

  const requestReveal = useCallback(async () => {
    setError('');
    setLoading(true);
    clearPlaintextState();
    const controller = new AbortController();
    abortControllerRef.current = controller;
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/reveal`, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ secret_path: secretPath }),
        signal: controller.signal
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (data.error === 'step_up_required' && data.authorize_url) {
          setAuthorizeUrl(data.authorize_url);
          setElevated(false);
          throw new Error('Fresh reauthentication is required before this secret can be revealed.');
        }
        if (response.status === 403) throw new Error('Access denied: no active grant authorizes this secret.');
        if (response.status === 503) throw new Error('Provider unavailable: reveal fails closed and no cached plaintext is returned.');
        if (response.status === 401) throw new Error('Sign in again to continue.');
        throw new Error(data.message || `Reveal request rejected with status ${response.status}`);
      }
      const payload = data as RevealPayload;
      setRevealedData(payload);
      setPlaintext(decodePlaintext(payload));
      setCountdown(payload.ttl_seconds && payload.ttl_seconds > 0 ? payload.ttl_seconds : 30);
    } catch (reason) {
      if (reason instanceof Error && reason.name === 'AbortError') return;
      setError(reason instanceof Error ? reason.message : 'Error executing transient reveal.');
    } finally {
      setLoading(false);
      abortControllerRef.current = null;
    }
  }, [vaultId, secretPath, clearPlaintextState]);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/v1/auth/session', { cache: 'no-store', credentials: 'same-origin' })
      .then(response => response.json())
      .then((session: { authenticated?: boolean; step_up?: StepUpState | null }) => {
        if (cancelled) return;
        const ready = session.step_up?.action === 'reveal_secret' && session.step_up?.resource === secretPath;
        setElevated(Boolean(ready));
        if (ready) void requestReveal();
      })
      .catch(() => { if (!cancelled) setElevated(false); });
    return () => { cancelled = true; };
  }, [secretPath, requestReveal]);

  useEffect(() => {
    if (countdown === null) return;
    if (countdown <= 0) {
      clearPlaintextState();
      return;
    }
    timerRef.current = setInterval(() => {
      setCountdown(previous => {
        if (previous === null || previous <= 1) {
          clearPlaintextState();
          return null;
        }
        return previous - 1;
      });
    }, 1000);
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [countdown, clearPlaintextState]);

  const startStepUp = useCallback(() => {
    sessionStorage.setItem(pendingKey, JSON.stringify({ vaultId, secretPath }));
    const query = new URLSearchParams({
      action: 'reveal',
      resource: secretPath,
      return_to: '/#vaults'
    });
    location.href = `/api/v1/auth/step-up?${query}`;
  }, [vaultId, secretPath]);

  const copyPlaintext = async () => {
    if (!plaintext) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(plaintext);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied; the value remains visible for manual copy.
    }
  };

  return (
    <div
      className="reveal-backdrop"
      style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(10, 15, 25, 0.85)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px' }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="reveal-dialog-title"
      data-testid="reveal-dialog"
    >
      <div className="panel" style={{ width: '100%', maxWidth: '560px', boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)', border: '1px solid #3a4b66' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div className="eyebrow">Transient Secret Reveal</div>
          <button type="button" className="badge" onClick={handleClose} aria-label="Close reveal dialog" data-testid="reveal-close-btn" style={{ cursor: 'pointer', background: 'transparent' }}>✕ Close</button>
        </div>

        <h2 id="reveal-dialog-title" style={{ marginTop: 0 }}>Secret: <code>{secretPath}</code></h2>
        <p className="intro" style={{ fontSize: '14px', marginBottom: '16px' }}>
          Vault: <code>{vaultId}</code>. The provider owns the sealed bytes; plaintext is decrypted on demand and cleared on close or timeout.
        </p>

        {error && (
          <section className="notice" role="alert" aria-live="assertive" style={{ margin: '14px 0' }}>
            <span className="dot" style={{ background: '#ff6b6b' }} />
            <span data-testid="reveal-error-msg">{error}</span>
          </section>
        )}

        {!revealedData ? (
          <div>
            <p className="muted">
              {elevated === null ? 'Checking session elevation…' : elevated ? 'Fresh step-up is active for this path.' : 'A fresh step-up reauthentication is required before the provider will decrypt this version.'}
            </p>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <button type="button" className="file-button" onClick={elevated ? requestReveal : startStepUp} disabled={loading || elevated === null} data-testid="request-reveal-btn">
                {loading ? 'Decrypting transient payload…' : elevated ? 'Reveal Secret' : 'Re-authenticate & Reveal'}
              </button>
              {authorizeUrl && (
                <a className="text-link" href={authorizeUrl} onClick={() => sessionStorage.setItem(pendingKey, JSON.stringify({ vaultId, secretPath }))}>
                  Continue with the identity provider
                </a>
              )}
              <button type="button" onClick={handleClose} style={{ background: 'transparent', color: '#b8c4d5', border: '1px solid #3a4860', borderRadius: '9px', padding: '11px 18px' }}>
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div data-testid="revealed-payload-container" style={{ marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', background: '#162338', borderRadius: '8px', marginBottom: '12px' }}>
              <span className="state active">Decrypted · v{revealedData.version} · {revealedData.classification}</span>
              <span className="task-id" data-testid="reveal-countdown" style={{ fontWeight: 'bold' }}>Auto-clearing in {countdown}s</span>
            </div>
            <div style={{ background: '#050a14', border: '1px solid #2d3f5d', borderRadius: '8px', padding: '14px', fontFamily: 'ui-monospace, monospace', fontSize: '15px', color: '#80e6c4', wordBreak: 'break-all', marginBottom: '16px' }} data-testid="plaintext-display">
              {plaintext}
            </div>
            <p className="muted">Algorithm: {revealedData.algorithm} · No-store · Digest {revealedData.metadata_digest.slice(0, 16)}…</p>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
              <button type="button" className="file-button" onClick={copyPlaintext} data-testid="copy-plaintext-btn">{copied ? 'Copied to Clipboard!' : 'Copy Plaintext'}</button>
              <button type="button" onClick={handleClose} data-testid="close-and-clear-btn" style={{ background: '#2b1b1b', color: '#ff9999', border: '1px solid #5a3030', borderRadius: '9px', padding: '11px 18px' }}>Close &amp; Zero Plaintext</button>
              <button type="button" onClick={handleLogout} data-testid="logout-and-purge-btn" style={{ background: 'transparent', color: '#94a5bc', border: '1px solid #3a4860', borderRadius: '9px', padding: '11px 18px', marginLeft: 'auto' }}>Logout Session</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Reveal;
