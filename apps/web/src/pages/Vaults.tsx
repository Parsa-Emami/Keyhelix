import { useEffect, useState } from 'react';
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

export function Vaults({ vaultId = 'vault-prod', onSelectSecret, onLogout }: VaultsProps) {
  const [secrets, setSecrets] = useState<SecretSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [search, setSearch] = useState<string>('');
  const [classificationFilter, setClassificationFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [activeRevealSecret, setActiveRevealSecret] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function loadMetadata() {
      setLoading(true);
      setError('');
      try {
        // Invariant F14: fetch ONLY safe metadata summary. Plaintext is NEVER fetched to render list.
        const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/metadata`, {
          cache: 'no-store',
          headers: {
            'Accept': 'application/json'
          }
        });
        if (!response.ok) {
          if (response.status === 401 || response.status === 403) {
            throw new Error('Access denied to vault metadata.');
          }
          if (response.status === 503) {
            throw new Error('Vault service unavailable.');
          }
          throw new Error('Failed to load vault metadata.');
        }
        const data = await response.json();
        if (!cancelled) {
          const list: SecretSummary[] = Array.isArray(data) ? data : (data.secrets || []);
          setSecrets(list);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Error loading vault metadata.');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadMetadata();
    return () => {
      cancelled = true;
    };
  }, [vaultId]);

  const filteredSecrets = secrets.filter(sec => {
    const matchesSearch = search === '' || sec.secret_path.toLowerCase().includes(search.toLowerCase());
    const matchesClass = classificationFilter === 'all' || sec.classification.toLowerCase() === classificationFilter.toLowerCase();
    const status = (sec.status || 'ACTIVE').toLowerCase();
    const matchesStatus = statusFilter === 'all' || status === statusFilter.toLowerCase();
    return matchesSearch && matchesClass && matchesStatus;
  });

  return (
    <div className="vaults-console" data-testid="vaults-console">
      <div className="eyebrow">Vault Metadata · Zero Plaintext</div>
      <h2>Vault Secrets: <code>{vaultId}</code></h2>
      <p className="intro">
        Authorized metadata stream for vault secrets. In compliance with security invariant F14, secret payloads are never fetched to render this list.
      </p>

      {error && (
        <section className="notice" role="alert" aria-live="assertive">
          <span className="dot" style={{ background: '#ff6b6b' }} />
          {error}
        </section>
      )}

      <div className="filters">
        <label>
          Search secret paths
          <input
            type="search"
            aria-label="Search secret paths"
            placeholder="e.g. payment/api-key"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </label>

        <label>
          Classification
          <select
            aria-label="Filter by classification"
            value={classificationFilter}
            onChange={e => setClassificationFilter(e.target.value)}
          >
            <option value="all">All classifications</option>
            <option value="restricted">Restricted</option>
            <option value="confidential">Confidential</option>
            <option value="internal">Internal</option>
            <option value="public">Public</option>
          </select>
        </label>

        <label>
          Status
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
          >
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="deleted">Deleted (Retained)</option>
            <option value="destroyed">Destroyed</option>
          </select>
        </label>
      </div>

      <p aria-live="polite" className="muted" data-testid="secret-count">
        {loading ? 'Loading vault metadata…' : `${filteredSecrets.length} of ${secrets.length} secrets available`}
      </p>

      {!loading && !error && filteredSecrets.length === 0 && (
        <p className="muted" role="status">No matching secrets found in vault.</p>
      )}

      <ol className="tasks secrets-list" aria-label="Secret metadata entries">
        {filteredSecrets.map(sec => {
          const status = sec.status || 'ACTIVE';
          return (
            <li key={sec.secret_path} className="secret-item" data-testid={`secret-${sec.secret_path}`}>
              <div className="task-line">
                <span className="task-id">v{sec.version}</span>
                <h2><code>{sec.secret_path}</code></h2>
                <span className={`state ${status.toLowerCase()}`}>{status}</span>
                <span className="badge">{sec.classification}</span>
              </div>
              <p className="muted">
                Created: {new Date(sec.created_at).toLocaleString()} · Digest: <code>{sec.metadata_digest.slice(0, 16)}…</code>
              </p>
              <button
                type="button"
                className="file-button"
                style={{ marginTop: '8px' }}
                data-testid={`reveal-btn-${sec.secret_path}`}
                onClick={() => {
                  setActiveRevealSecret(sec.secret_path);
                  if (onSelectSecret) onSelectSecret(sec.secret_path);
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
