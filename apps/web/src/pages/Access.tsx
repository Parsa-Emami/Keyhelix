import { useEffect, useState } from 'react';

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
  prior_kek_retirable?: boolean;
}

export interface AccessProps {
  vaultId?: string;
}

export function Access({ vaultId = 'vault-prod' }: AccessProps) {
  const [grants, setGrants] = useState<Grant[]>([]);
  const [rotations, setRotations] = useState<RotationJob[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [resumingJobId, setResumingJobId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchData() {
      setLoading(true);
      setError('');
      try {
        const [grantsRes, rotationsRes] = await Promise.all([
          fetch(`/api/vaults/${encodeURIComponent(vaultId)}/grants`, {
            cache: 'no-store',
            headers: { 'Accept': 'application/json' },
          }),
          fetch(`/api/vaults/${encodeURIComponent(vaultId)}/rotations`, {
            cache: 'no-store',
            headers: { 'Accept': 'application/json' },
          }),
        ]);

        if (!grantsRes.ok || !rotationsRes.ok) {
          if (grantsRes.status === 503 || rotationsRes.status === 503) {
            throw new Error('Access provider unavailable: Operations fail closed.');
          }
          if (grantsRes.status === 401 || rotationsRes.status === 401) {
            throw new Error('Step-up authentication required for access management.');
          }
          throw new Error('Failed to load access and rotation metadata.');
        }

        const grantsData = await grantsRes.json();
        const rotationsData = await rotationsRes.json();

        if (!cancelled) {
          setGrants(Array.isArray(grantsData) ? grantsData : (grantsData.grants || []));
          setRotations(Array.isArray(rotationsData) ? rotationsData : (rotationsData.rotations || []));
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
  }, [vaultId]);

  const handleResumeRotation = async (jobId: string) => {
    setResumingJobId(jobId);
    try {
      const response = await fetch(`/api/vaults/${encodeURIComponent(vaultId)}/rotations/${encodeURIComponent(jobId)}/resume`, {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      });
      if (!response.ok) {
        throw new Error('Failed to resume rotation: Provider remains unavailable.');
      }
      // Refresh local state if success
      const refreshed: RotationJob = await response.json();
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

      {error && (
        <section className="notice" role="alert" aria-live="assertive" data-testid="provider-error-alert">
          <span className="dot" style={{ background: '#ff6b6b' }} />
          <span>{error}</span>
        </section>
      )}

      {/* Rotation Jobs Section */}
      <section className="panel" style={{ marginTop: '24px' }}>
        <div className="eyebrow">Key & Version Rotations</div>
        <h3>Resumable Rotation Lifecycle</h3>
        <p className="muted">
          Partial rotations preserve durable checkpoints. Retiring the prior KEK is strictly prohibited until 100% of envelopes are rewrapped and verified.
        </p>

        {loading ? (
          <p className="muted" data-testid="loading-indicator">Loading rotation lifecycle…</p>
        ) : rotations.length === 0 ? (
          <p className="muted" data-testid="no-rotations">No rotation jobs recorded.</p>
        ) : (
          <div className="rotations-list" data-testid="rotations-list">
            {rotations.map(job => {
              const isComplete = job.state === 'COMPLETE';
              const isPartial = !isComplete && job.rewrapped_secrets > 0 && job.rewrapped_secrets < job.total_secrets;
              const isFailed = job.state === 'FAILED_ROLLBACK' || !!job.last_error;

              return (
                <div
                  key={job.job_id}
                  className="panel"
                  data-testid={`rotation-job-${job.job_id}`}
                  style={{
                    border: isComplete ? '1px solid #386e51' : isPartial ? '1px solid #c99a38' : '1px solid #8c3b3b',
                    background: '#0d1522',
                    marginTop: '12px',
                    padding: '18px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span className="task-id"><code>{job.job_id}</code></span>
                      <span
                        className={`state ${isComplete ? 'verified' : isPartial ? 'partial' : 'failed'}`}
                        data-testid={`job-state-${job.job_id}`}
                        style={{
                          background: isComplete ? '#1a3324' : isPartial ? '#3b2f15' : '#3d1c1c',
                          color: isComplete ? '#9ce3b9' : isPartial ? '#ffd166' : '#ff9999',
                          borderColor: isComplete ? '#386e51' : isPartial ? '#c99a38' : '#8c3b3b',
                        }}
                      >
                        {isComplete ? 'COMPLETE' : isPartial ? 'PARTIAL' : job.state}
                      </span>
                    </div>
                    <span className="badge">Target: {job.target_kek_id} ({job.target_kek_version})</span>
                  </div>

                  {/* Progress indicator */}
                  <div style={{ margin: '14px 0' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '6px' }}>
                      <span>Rewrapped: {job.rewrapped_secrets} of {job.total_secrets} secrets</span>
                      <span>{Math.round((job.rewrapped_secrets / job.total_secrets) * 100)}%</span>
                    </div>
                    <div style={{ background: '#192538', height: '8px', borderRadius: '4px', overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${Math.round((job.rewrapped_secrets / job.total_secrets) * 100)}%`,
                          background: isComplete ? '#80e6c4' : '#ffd166',
                          height: '100%',
                        }}
                      />
                    </div>
                  </div>

                  {/* F16 Alert: Partial or Incomplete warning */}
                  {!isComplete && (
                    <div
                      role="alert"
                      className="notice"
                      data-testid={`rotation-warning-${job.job_id}`}
                      style={{
                        margin: '12px 0',
                        background: '#231c12',
                        borderColor: '#5a431c',
                        color: '#f0c27b',
                      }}
                    >
                      <span className="dot" style={{ background: '#ffd166' }} />
                      <div>
                        <strong>Incomplete rotation:</strong> Prior KEK cannot be retired. Operation paused at checkpoint{' '}
                        <code>{job.checkpoint_secret || 'unknown'}</code>.
                        {job.last_error && <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#ffb2b2' }}>{job.last_error}</p>}
                      </div>
                    </div>
                  )}

                  {isComplete && (
                    <p className="muted" data-testid={`rotation-success-${job.job_id}`} style={{ color: '#9ce3b9', fontSize: '13px' }}>
                      ✓ All envelopes rewrapped and verified. Prior KEK can be safely retired.
                    </p>
                  )}

                  {isPartial && (
                    <button
                      type="button"
                      className="file-button"
                      onClick={() => handleResumeRotation(job.job_id)}
                      disabled={resumingJobId === job.job_id}
                      data-testid={`resume-btn-${job.job_id}`}
                      style={{ marginTop: '8px' }}
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
      <section className="panel" style={{ marginTop: '24px' }}>
        <div className="eyebrow">Access Control Grants</div>
        <h3>Provider Grants & Revocations</h3>
        <p className="muted">
          Least-privilege authorizations bound to synthetic operator sessions. Revoked privileges fail closed immediately.
        </p>

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
                      style={{
                        background: isRevoked ? '#3d1c1c' : '#1a3324',
                        color: isRevoked ? '#ff9999' : '#9ce3b9',
                        borderColor: isRevoked ? '#8c3b3b' : '#386e51',
                      }}
                    >
                      {grant.status}
                    </span>
                  </div>
                  <p className="muted" style={{ wordBreak: 'break-word', overflowWrap: 'anywhere' }}>
                    Scopes: {grant.allowed_scopes.map(s => <code key={s} style={{ marginRight: '6px', wordBreak: 'break-all' }}>{s}</code>)} · Expires: {new Date(grant.expires_at).toLocaleString()}
                    {grant.revoked_at && ` · Revoked at: ${new Date(grant.revoked_at).toLocaleString()}`}
                  </p>
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
