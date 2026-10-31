import { useCallback, useEffect, useState } from 'react';

export interface Grant {
  grant_id: string;
  subject: string;
  email: string;
  vault_role: string;
  allowed_scopes: string[];
  created_at: string;
  expires_at: string;
  status: 'ACTIVE' | 'REVOKED' | string;
  revoked_at?: string;
}

export interface RotationJob {
  job_id: string;
  vault_id: string;
  target_kek_id: string;
  target_kek_version: string;
  state: 'PLANNED' | 'REWRAPPING' | 'VERIFYING' | 'COMPLETE' | 'FAILED_ROLLBACK' | string;
  total_secrets: number;
  rewrapped_secrets: number;
  checkpoint_secret?: string;
  started_at: string;
  completed_at?: string;
  last_error?: string;
  last_error_code?: string;
  prior_kek_retirable?: boolean;
}

export interface AccessProps {
  vaultId?: string;
}

const pendingCreateGrantKey = 'keyhelix.pendingCreateGrant';
const pendingStartRotationKey = 'keyhelix.pendingStartRotation';

export function Access({ vaultId = 'vault-prod' }: AccessProps) {
  const [grants, setGrants] = useState<Grant[]>([]);
  const [rotations, setRotations] = useState<RotationJob[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [notice, setNotice] = useState<string>('');
  const [resumingJobId, setResumingJobId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [needsSignIn, setNeedsSignIn] = useState(false);

  // Create Grant form state
  const [principalEmail, setPrincipalEmail] = useState('bob@keyhelix.local');
  const [scopePattern, setScopePattern] = useState('app/prod/*');
  const [expiresHours, setExpiresHours] = useState('24');
  const [creatingGrant, setCreatingGrant] = useState(false);

  // Start Rotation form state
  const [targetKekId, setTargetKekId] = useState('kek-v1-openbao');
  const [targetKekVersion, setTargetKekVersion] = useState('v2');
  const [startingRotation, setStartingRotation] = useState(false);

  const submitCreateGrant = useCallback(async (principal: string, scope: string, ttlSeconds: number) => {
    setCreatingGrant(true);
    setError('');
    setNotice('');
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/grants`, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          principal_id: principal.trim(),
          permissions: ['secret:read', scope.trim()],
          expires_in_seconds: ttlSeconds
        })
      });
      const data = await response.json().catch(() => ({}));
      if (response.status === 401 && data.authorize_url) {
        sessionStorage.setItem(pendingCreateGrantKey, JSON.stringify({ principal, scope, ttlSeconds }));
        location.href = data.authorize_url;
        return;
      }
      if (!response.ok) {
        throw new Error(data.message || 'The member grant could not be created.');
      }
      const created = data as Grant;
      setGrants(previous => [created, ...previous.filter(item => item.grant_id !== created.grant_id)]);
      setNotice(`Created grant ${created.grant_id} for ${created.email}.`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'The member grant could not be created.');
    } finally {
      setCreatingGrant(false);
    }
  }, [vaultId]);

  const submitStartRotation = useCallback(async (kekId: string, kekVersion: string) => {
    setStartingRotation(true);
    setError('');
    setNotice('');
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/rotations`, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          target_kek_id: kekId.trim(),
          target_kek_version: kekVersion.trim()
        })
      });
      const data = await response.json().catch(() => ({}));
      if (response.status === 401 && data.authorize_url) {
        sessionStorage.setItem(pendingStartRotationKey, JSON.stringify({ kekId, kekVersion }));
        location.href = data.authorize_url;
        return;
      }
      if (!response.ok) {
        throw new Error(data.message || 'Failed to start key rotation job.');
      }
      const created = data as RotationJob;
      setRotations(previous => [created, ...previous.filter(item => item.job_id !== created.job_id)]);
      setNotice(`Rotation job ${created.job_id} completed with state ${created.state}.`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to start key rotation job.');
    } finally {
      setStartingRotation(false);
    }
  }, [vaultId]);

  const revoke = useCallback(async (grantId: string) => {
    setRevokingId(grantId);
    setError('');
    setNotice('');
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/grants/${encodeURIComponent(grantId)}/revoke`, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await response.json().catch(() => ({}));
      if (response.status === 401 && data.authorize_url) {
        sessionStorage.setItem('keyhelix.pendingRevoke', grantId);
        location.href = data.authorize_url;
        return;
      }
      if (!response.ok) throw new Error(data.message || 'The grant could not be revoked.');
      setGrants(previous => previous.map(grant => grant.grant_id === grantId ? { ...grant, status: 'REVOKED', revoked_at: new Date().toISOString() } : grant));
      setNotice(`Revoked grant ${grantId}.`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'The grant could not be revoked.');
    } finally {
      setRevokingId(null);
    }
  }, [vaultId]);

  useEffect(() => {
    let cancelled = false;

    async function fetchData(attempted = false) {
      setLoading(true);
      setError('');
      try {
        const [grantsRes, rotationsRes] = await Promise.all([
          fetch(`/api/vaults/${encodeURIComponent(vaultId)}/grants`, {
            cache: 'no-store',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
          }),
          fetch(`/api/vaults/${encodeURIComponent(vaultId)}/rotations`, {
            cache: 'no-store',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
          }),
        ]);

        if (!grantsRes.ok || !rotationsRes.ok) {
          if (grantsRes.status === 503 || rotationsRes.status === 503) {
            throw new Error('Access provider unavailable: Operations fail closed.');
          }
          if (grantsRes.status === 401) {
            setNeedsSignIn(true);
            throw new Error('Sign in as the vault administrator to inspect grants.');
          }
          if (grantsRes.status === 403) throw new Error('Only the vault administrator can inspect grants.');
          throw new Error('Failed to load access and rotation metadata.');
        }
        setNeedsSignIn(false);

        const grantsData = await grantsRes.json();
        const rotationsData = await rotationsRes.json();

        if (!cancelled) {
          const list: Grant[] = Array.isArray(grantsData) ? grantsData : (grantsData.grants || []);
          setGrants(list);
          setRotations(Array.isArray(rotationsData) ? rotationsData : (rotationsData.rotations || []));

          if (!attempted) {
            const pendingRevoke = sessionStorage.getItem('keyhelix.pendingRevoke');
            if (pendingRevoke) {
              sessionStorage.removeItem('keyhelix.pendingRevoke');
              const target = list.find(grant => grant.grant_id === pendingRevoke);
              if (target && target.status !== 'REVOKED') void revoke(pendingRevoke);
            }

            const pendingCreateRaw = sessionStorage.getItem(pendingCreateGrantKey);
            if (pendingCreateRaw) {
              sessionStorage.removeItem(pendingCreateGrantKey);
              try {
                const parsed = JSON.parse(pendingCreateRaw);
                if (parsed?.principal && parsed?.scope) {
                  void submitCreateGrant(parsed.principal, parsed.scope, Number(parsed.ttlSeconds) || 3600);
                }
              } catch {
                // Ignore malformed sessionStorage state
              }
            }

            const pendingRotRaw = sessionStorage.getItem(pendingStartRotationKey);
            if (pendingRotRaw) {
              sessionStorage.removeItem(pendingStartRotationKey);
              try {
                const parsed = JSON.parse(pendingRotRaw);
                if (parsed?.kekId) {
                  void submitStartRotation(parsed.kekId, parsed.kekVersion || 'v2');
                }
              } catch {
                // Ignore malformed sessionStorage state
              }
            }
          }
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Error querying provider.');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void fetchData();
    return () => {
      cancelled = true;
    };
  }, [vaultId, revoke, submitCreateGrant, submitStartRotation]);

  const handleResumeRotation = async (jobId: string) => {
    setResumingJobId(jobId);
    setError('');
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/rotations/${encodeURIComponent(jobId)}/resume`, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({})
      });
      const data = await response.json().catch(() => ({}));
      if (response.status === 401 && data.authorize_url) {
        location.href = data.authorize_url;
        return;
      }
      if (!response.ok) {
        throw new Error(data.message || 'Failed to resume rotation: Provider remains unavailable.');
      }
      const refreshed = data as RotationJob;
      setRotations(prev => prev.map(r => (r.job_id === refreshed.job_id ? refreshed : r)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Error resuming rotation.');
    } finally {
      setResumingJobId(null);
    }
  };

  return (
    <div className="access-console" data-testid="access-console">
      <div className="eyebrow">Provider Operations & Access Control · Requirement F16</div>
      <h2>Access & Rotation Governance: <code>{vaultId}</code></h2>
      <p className="intro">
        Audit member authorizations and key version rotations. In compliance with Requirement F16, partial and failed provider operations are visible and cannot look like success.
      </p>

      {needsSignIn && (
        <section className="notice" role="status">
          <span className="dot" />
          <span>Sign in as the vault administrator to manage grants. </span>
          <a className="text-link" href="/api/v1/auth/login?return_to=/%23access">Sign in</a>
        </section>
      )}

      {error && (
        <section className="notice" role="alert" aria-live="assertive" data-testid="provider-error-alert">
          <span className="dot dot-error" />
          <span>{error}</span>
        </section>
      )}

      {notice && <p role="status" className="muted" data-testid="access-notice">{notice}</p>}

      {/* Rotation Jobs Section */}
      <section className="panel section-panel">
        <div className="eyebrow">Key & Version Rotations</div>
        <h3>Resumable Rotation Lifecycle</h3>
        <p className="muted">
          Partial rotations preserve durable checkpoints. Retiring the prior KEK is strictly prohibited until 100% of envelopes are rewrapped and verified.
        </p>

        <form
          className="filters form-panel"
          aria-label="Start key rotation"
          onSubmit={event => {
            event.preventDefault();
            void submitStartRotation(targetKekId, targetKekVersion);
          }}
        >
          <label>
            Target KEK ID
            <input
              value={targetKekId}
              onChange={event => setTargetKekId(event.target.value)}
              aria-label="Target KEK ID"
              placeholder="kek-v1-openbao"
            />
          </label>
          <label>
            Target KEK Version
            <input
              value={targetKekVersion}
              onChange={event => setTargetKekVersion(event.target.value)}
              aria-label="Target KEK Version"
              placeholder="v2"
            />
          </label>
          <div className="inline-actions">
            <button
              type="submit"
              className="file-button"
              disabled={startingRotation || needsSignIn}
              data-testid="start-rotation-btn"
            >
              {startingRotation ? 'Rotating envelopes…' : 'Start Key Rotation (step-up)'}
            </button>
          </div>
        </form>

        {loading ? (
          <p className="muted" data-testid="loading-indicator">Loading rotation lifecycle…</p>
        ) : rotations.length === 0 ? (
          <p className="muted" data-testid="no-rotations">No rotation jobs recorded.</p>
        ) : (
          <div className="rotations-list" data-testid="rotations-list">
            {rotations.map(job => {
              const isComplete = job.state === 'COMPLETE';
              const isPartial = !isComplete && job.rewrapped_secrets > 0 && job.rewrapped_secrets < job.total_secrets;
              const isFailed = job.state === 'FAILED_ROLLBACK' || Boolean(job.last_error) || Boolean(job.last_error_code);
              const percent = job.total_secrets > 0 ? Math.round((job.rewrapped_secrets / job.total_secrets) * 100) : 0;
              const cardModifier = isComplete ? 'complete' : isPartial ? 'partial' : isFailed ? 'failed' : 'partial';

              return (
                <div
                  key={job.job_id}
                  className={`panel rotation-card ${cardModifier}`}
                  data-testid={`rotation-job-${job.job_id}`}
                >
                  <div className="rotation-header">
                    <div className="rotation-id-group">
                      <span className="task-id"><code>{job.job_id}</code></span>
                      <span
                        className={`state ${isComplete ? 'verified' : isPartial ? 'partial' : 'failed'}`}
                        data-testid={`job-state-${job.job_id}`}
                      >
                        {isComplete ? 'COMPLETE' : isPartial ? 'PARTIAL' : job.state}
                      </span>
                    </div>
                    <span className="badge">Target: {job.target_kek_id} ({job.target_kek_version})</span>
                  </div>

                  {/* Progress indicator */}
                  <div className="rotation-progress">
                    <div className="rotation-progress-labels">
                      <span>Rewrapped: {job.rewrapped_secrets} of {job.total_secrets} secrets</span>
                      <span>{percent}%</span>
                    </div>
                    <div className="rotation-progress-track">
                      <div
                        className={`rotation-progress-bar ${isComplete ? 'complete' : isFailed ? 'failed' : ''}`}
                        style={{ width: `${percent}%` } as React.CSSProperties}
                      />
                    </div>
                  </div>

                  {/* F16 Alert: Partial or Incomplete warning */}
                  {!isComplete && (
                    <div
                      role="alert"
                      className={`notice ${isFailed ? 'notice-danger' : 'notice-warning'}`}
                      data-testid={`rotation-warning-${job.job_id}`}
                    >
                      <span className={`dot ${isFailed ? 'dot-error' : 'dot-warning'}`} />
                      <div>
                        <strong>Incomplete rotation:</strong> Prior KEK cannot be retired. Operation paused at checkpoint{' '}
                        <code>{job.checkpoint_secret || 'unknown'}</code>.
                        {(job.last_error || job.last_error_code) && (
                          <p className="rotation-error-detail">{job.last_error || job.last_error_code}</p>
                        )}
                      </div>
                    </div>
                  )}

                  {isComplete && (
                    <p className="muted rotation-complete-msg" data-testid={`rotation-success-${job.job_id}`}>
                      ✓ All envelopes rewrapped and verified. Prior KEK can be safely retired.
                    </p>
                  )}

                  {!isComplete && (
                    <button
                      type="button"
                      className="file-button"
                      onClick={() => void handleResumeRotation(job.job_id)}
                      disabled={resumingJobId === job.job_id}
                      data-testid={`resume-btn-${job.job_id}`}
                    >
                      {resumingJobId === job.job_id ? 'Resuming…' : 'Resume Rotation from Checkpoint'}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Member Grants Section */}
      <section className="panel section-panel">
        <div className="eyebrow">Access Control Grants</div>
        <h3>Provider Grants & Revocations</h3>
        <p className="muted">
          Least-privilege authorizations bound to synthetic operator sessions. Revoked privileges fail closed immediately.
        </p>

        <form
          className="filters form-panel"
          aria-label="Create member grant"
          onSubmit={event => {
            event.preventDefault();
            const hours = Math.max(1, Number(expiresHours) || 24);
            void submitCreateGrant(principalEmail, scopePattern, hours * 3600);
          }}
        >
          <label>
            Member principal (email)
            <input
              value={principalEmail}
              onChange={event => setPrincipalEmail(event.target.value)}
              aria-label="Member principal"
              placeholder="bob@keyhelix.local"
            />
          </label>
          <label>
            Allowed path scope
            <input
              value={scopePattern}
              onChange={event => setScopePattern(event.target.value)}
              aria-label="Allowed path scope"
              placeholder="app/prod/*"
            />
          </label>
          <label>
            TTL (hours)
            <input
              type="number"
              min={1}
              max={720}
              value={expiresHours}
              onChange={event => setExpiresHours(event.target.value)}
              aria-label="Grant TTL hours"
            />
          </label>
          <div className="inline-actions">
            <button
              type="submit"
              className="file-button"
              disabled={creatingGrant || needsSignIn}
              data-testid="create-grant-btn"
            >
              {creatingGrant ? 'Creating grant…' : 'Create Member Grant (step-up)'}
            </button>
          </div>
        </form>

        {loading ? (
          <p className="muted">Loading member grants…</p>
        ) : grants.length === 0 ? (
          <p className="muted" data-testid="no-grants">No active grants found.</p>
        ) : (
          <ol className="tasks grants-list" aria-label="Member grants list" data-testid="grants-list">
            {grants.map(grant => {
              const isRevoked = grant.status === 'REVOKED';
              return (
                <li key={grant.grant_id} className="grant-item" data-testid={`grant-${grant.grant_id}`}>
                  <div className="task-line">
                    <span className="task-id"><code>{grant.grant_id}</code></span>
                    <h2><code>{grant.email}</code> ({grant.vault_role})</h2>
                    <span
                      className={`state ${isRevoked ? 'revoked' : 'verified'}`}
                      data-testid={`grant-status-${grant.grant_id}`}
                    >
                      {grant.status}
                    </span>
                  </div>
                  <p className="muted grant-meta">
                    Scopes: {grant.allowed_scopes.map(s => <code key={s} className="scope-chip">{s}</code>)} · Expires: {new Date(grant.expires_at).toLocaleString()}
                    {grant.revoked_at && ` · Revoked at: ${new Date(grant.revoked_at).toLocaleString()}`}
                  </p>
                  {!isRevoked && (
                    <div className="inline-actions">
                      <button
                        type="button"
                        className="file-button"
                        onClick={() => void revoke(grant.grant_id)}
                        disabled={revokingId === grant.grant_id}
                        data-testid={`revoke-grant-${grant.grant_id}`}
                      >
                        {revokingId === grant.grant_id ? 'Revoking…' : 'Revoke grant (step-up)'}
                      </button>
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
        )}
      </section>
    </div>
  );
}

export default Access;
