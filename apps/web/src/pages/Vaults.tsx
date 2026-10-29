import { useCallback, useEffect, useState } from 'react';
import { Reveal } from './Reveal';

export interface SecretSummary {
  vault_id: string;
  secret_path: string;
  version: number;
  classification: string;
  created_at: string;
  metadata_digest: string;
  status?: string;
}

export interface VaultsProps {
  vaultId?: string;
  onSelectSecret?: (secretPath: string) => void;
  onLogout?: () => void;
}

const pendingKey = 'keyhelix.pendingReveal';

export function Vaults({ vaultId = 'vault-prod', onSelectSecret, onLogout }: VaultsProps) {
  const [secrets, setSecrets] = useState<SecretSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [needsSignIn, setNeedsSignIn] = useState(false);
  const [search, setSearch] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [activeRevealSecret, setActiveRevealSecret] = useState<string | null>(null);
  const [draftPath, setDraftPath] = useState('app/prod/');
  const [draftValue, setDraftValue] = useState('');
  const [draftClassification, setDraftClassification] = useState('restricted');
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState('');

  const loadMetadata = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/metadata`, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' }
      });
      if (response.status === 401) {
        setNeedsSignIn(true);
        setSecrets([]);
        return;
      }
      if (!response.ok) {
        if (response.status === 403) throw new Error('Access denied to vault metadata.');
        if (response.status === 503) throw new Error('Vault runtime unavailable: the engine or a required provider is down.');
        throw new Error('Failed to load vault metadata.');
      }
      setNeedsSignIn(false);
      const data = await response.json();
      setSecrets(Array.isArray(data) ? data : (data.secrets || []));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Error loading vault metadata.');
    } finally {
      setLoading(false);
    }
  }, [vaultId]);

  useEffect(() => {
    void loadMetadata();
  }, [loadMetadata]);

  useEffect(() => {
    try {
      const pending = JSON.parse(sessionStorage.getItem(pendingKey) ?? 'null');
      if (pending && pending.vaultId === vaultId && typeof pending.secretPath === 'string') {
        sessionStorage.removeItem(pendingKey);
        setActiveRevealSecret(pending.secretPath);
      }
    } catch {
      sessionStorage.removeItem(pendingKey);
    }
  }, [vaultId]);

  const existing = secrets.find(secret => secret.secret_path === draftPath);

  async function writeSecret(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    setNotice('');
    if (!draftPath.trim() || !draftValue) {
      setError('A canonical path and a non-empty value are required.');
      return;
    }
    setSaving(true);
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/secrets`, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          secret_path: draftPath.trim(),
          plaintext: draftValue,
          expected_version: existing?.version ?? 0,
          classification: draftClassification
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 401) {
          setNeedsSignIn(true);
          throw new Error('Sign in before writing secrets.');
        }
        if (response.status === 409) throw new Error('The secret changed since this page loaded. Refresh and retry.');
        if (response.status === 503) throw new Error('Provider unavailable: the write failed closed.');
        throw new Error(data.message || 'The secret could not be written.');
      }
      setDraftValue('');
      setNotice(`Wrote ${data.secret_path} version ${data.version}.`);
      await loadMetadata();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The secret could not be written.');
    } finally {
      setSaving(false);
    }
  }

  const statuses = [...new Set(secrets.map(secret => (secret.status || 'ACTIVE').toLowerCase()))].sort();

  const filteredSecrets = secrets.filter(secret => {
    const matchesSearch = search === '' || secret.secret_path.toLowerCase().includes(search.toLowerCase());
    const matchesClass = classificationFilter === 'all' || secret.classification.toLowerCase() === classificationFilter.toLowerCase();
    const status = (secret.status || 'ACTIVE').toLowerCase();
    const matchesStatus = statusFilter === 'all' || status === statusFilter.toLowerCase();
    return matchesSearch && matchesClass && matchesStatus;
  });

  return (
    <div className="vaults-console" data-testid="vaults-console">
      <div className="eyebrow">Vault Metadata · Provider-owned bytes</div>
      <h2>Vault Secrets: <code>{vaultId}</code></h2>
      <p className="intro">
        Authorized metadata is listed without fetching plaintext. Reveal requires a fresh step-up reauthentication and an active grant for member accounts.
      </p>

      {needsSignIn && (
        <section className="notice" role="status">
          <span className="dot" />
          <span>Sign in with the local identity provider to inspect or write vault secrets. </span>
          <a className="text-link" href="/api/v1/auth/login?return_to=/%23vaults">Sign in</a>
        </section>
      )}

      {error && (
        <section className="notice" role="alert" aria-live="assertive">
          <span className="dot" style={{ background: '#ff6b6b' }} />
          {error}
        </section>
      )}

      {notice && <p role="status" className="muted">{notice}</p>}

      <form className="panel" onSubmit={writeSecret} aria-label="Write a versioned secret" style={{ marginBottom: '20px' }}>
        <div className="eyebrow">Scoped write</div>
        <h3>Create or add a new secret version</h3>
        <p className="muted">The engine seals the value with a fresh DEK, stores the wrapped key in OpenBao and writes only metadata here.</p>
        <div className="filters">
          <label>
            Secret path
            <input value={draftPath} onChange={event => setDraftPath(event.target.value)} aria-label="Secret path" placeholder="app/prod/database-url" />
          </label>
          <label>
            Classification
            <select value={draftClassification} onChange={event => setDraftClassification(event.target.value)} aria-label="Secret classification">
              <option value="restricted">Restricted</option>
              <option value="confidential">Confidential</option>
              <option value="internal">Internal</option>
            </select>
          </label>
        </div>
        <label style={{ display: 'block', marginTop: '10px' }}>
          Secret value
          <textarea value={draftValue} onChange={event => setDraftValue(event.target.value)} aria-label="Secret value" rows={3} placeholder="Synthetic value only in this local workspace" style={{ width: '100%', marginTop: '6px' }} />
        </label>
        <p className="muted">{existing ? `Updating existing version ${existing.version}; the next version is ${existing.version + 1}.` : 'This path does not exist yet; the write creates version 1.'}</p>
        <button type="submit" className="file-button" disabled={saving || needsSignIn} data-testid="write-secret-btn">
          {saving ? 'Sealing and writing…' : existing ? 'Write next version' : 'Create secret'}
        </button>
      </form>

      <div className="filters">
        <label>
          Search secret paths
          <input type="search" aria-label="Search secret paths" placeholder="e.g. payment/api-key" value={search} onChange={event => setSearch(event.target.value)} />
        </label>
        <label>
          Classification
          <select aria-label="Filter by classification" value={classificationFilter} onChange={event => setClassificationFilter(event.target.value)}>
            <option value="all">All classifications</option>
            <option value="restricted">Restricted</option>
            <option value="confidential">Confidential</option>
            <option value="internal">Internal</option>
          </select>
        </label>
        <label>
          Status
          <select aria-label="Filter by status" value={statusFilter} onChange={event => setStatusFilter(event.target.value)}>
            <option value="all">All statuses</option>
            {statuses.map(status => <option key={status} value={status}>{status.charAt(0).toUpperCase() + status.slice(1)}</option>)}
          </select>
        </label>
      </div>

      <p aria-live="polite" className="muted" data-testid="secret-count">
        {loading ? 'Loading vault metadata…' : `${filteredSecrets.length} of ${secrets.length} secrets available`}
      </p>

      {!loading && !error && !needsSignIn && filteredSecrets.length === 0 && (
        <p className="muted" role="status">No matching secrets found in vault.</p>
      )}

      <ol className="tasks secrets-list" aria-label="Secret metadata entries">
        {filteredSecrets.map(secret => {
          const status = secret.status || 'ACTIVE';
          return (
            <li key={secret.secret_path} className="secret-item" data-testid={`secret-${secret.secret_path}`}>
              <div className="task-line">
                <span className="task-id">v{secret.version}</span>
                <h2><code>{secret.secret_path}</code></h2>
                <span className={`state ${status.toLowerCase()}`}>{status}</span>
                <span className="badge">{secret.classification}</span>
              </div>
              <p className="muted">
                Created: {new Date(secret.created_at).toLocaleString()} · Digest: <code>{secret.metadata_digest.slice(0, 16)}…</code>
              </p>
              <button
                type="button"
                className="file-button"
                style={{ marginTop: '8px' }}
                data-testid={`reveal-btn-${secret.secret_path}`}
                onClick={() => {
                  setActiveRevealSecret(secret.secret_path);
                  if (onSelectSecret) onSelectSecret(secret.secret_path);
                }}
              >
                Inspect / Request Reveal
              </button>
            </li>
          );
        })}
      </ol>

      {activeRevealSecret && (
        <Reveal
          vaultId={vaultId}
          secretPath={activeRevealSecret}
          onClose={() => setActiveRevealSecret(null)}
          onLogout={() => {
            setActiveRevealSecret(null);
            if (onLogout) onLogout();
          }}
        />
      )}
    </div>
  );
}
export default Vaults;
