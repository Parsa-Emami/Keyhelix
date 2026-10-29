import { StrictMode, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import project from './generated/project.json';
import { validateRuntimeConfig, validateHealth } from './lib/runtime-config.mjs';
import { inspectJson } from './lib/preview.mjs';
import { Vaults } from './pages/Vaults';
import { Access } from './pages/Access';
import './styles.css';

type Runtime = { projectId: string; apiBasePath: string; engineEnabled: boolean; maxPreviewBytes: number };
type SessionUser = { email?: string; subject: string; vault_role?: string };
type SessionState = { authenticated: boolean; user?: SessionUser; step_up?: { action: string; resource: string; expires_at: string } | null };
type Route = 'workspace' | 'vaults' | 'access' | 'roadmap';
function route(): Route {
  if (location.hash === '#roadmap') return 'roadmap';
  if (location.hash === '#vaults') return 'vaults';
  if (location.hash === '#access') return 'access';
  return 'workspace';
}

function App({ config }: { config: Runtime }) {
  const [page, setPage] = useState<Route>(route);
  const [query, setQuery] = useState('');
  const [stage, setStage] = useState('all');
  const [preview, setPreview] = useState<{ name: string; bytes: number; fields: string[] } | null>(null);
  const [error, setError] = useState('');
  const [engine, setEngine] = useState('Checking engine runtime…');
  const [coreReady, setCoreReady] = useState(false);
  const [session, setSession] = useState<SessionState>({ authenticated: false });
  const busy = useRef(false);
  const generation = useRef(0);
  useEffect(() => {
    const onRoute = () => { setPage(route()); document.getElementById('content')?.focus(); };
    addEventListener('hashchange', onRoute);
    return () => removeEventListener('hashchange', onRoute);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    async function check() {
      try {
        const response = await fetch('/api/engine/health', {
          cache: 'no-store',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(2000)])
        });
        if (!response.ok) throw new Error('Engine unavailable');
        const health = validateHealth(await response.json());
        if (!controller.signal.aborted) {
          setEngine(`Engine runtime ${health.version} is running (${health.toolchain}).`);
          setCoreReady(health.coreReady);
        }
      } catch {
        if (!controller.signal.aborted) {
          setEngine('Engine runtime unavailable.');
          setCoreReady(false);
        }
      }
    }
    void check();
    const timer = setInterval(() => { void check(); }, 5000);
    return () => { controller.abort(); clearInterval(timer); };
  }, []);
  useEffect(() => {
    let cancelled = false;
    fetch('/api/v1/auth/session', { cache: 'no-store', credentials: 'same-origin' })
      .then(response => response.json())
      .then((value: SessionState) => { if (!cancelled) setSession(value); })
      .catch(() => { if (!cancelled) setSession({ authenticated: false }); });
    return () => { cancelled = true; };
  }, [page]);
  async function signOut() {
    try {
      await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    } finally {
      location.reload();
    }
  }
  async function importFile(file: File | undefined) {
    if (!file || busy.current) return;
    const current = ++generation.current;
    setError(''); setPreview(null);
    if (file.size > config.maxPreviewBytes) { setError('File exceeds the preview limit.'); return; }
    busy.current = true;
    try {
      const result = inspectJson(await file.text(), config.maxPreviewBytes);
      if (current === generation.current) setPreview({ name: file.name, fields: result.fields, bytes: result.bytes });
    } catch (reason) {
      if (current === generation.current) setError(reason instanceof Error ? reason.message : 'Unable to read this file.');
    } finally { busy.current = false; }
  }
  const tasks = project.tasks.filter(task => (stage === 'all' || task.stage === stage) && `${task.id} ${task.title}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="app" style={{ '--accent': project.accent } as React.CSSProperties}>
    <a className="skip" href="#content">Skip to content</a>
    <header><a className="brand" href="#workspace"><span className="mark" aria-hidden="true">{project.name.slice(0, 1)}</span>{project.name}</a><nav aria-label="Main"><a href="#workspace" aria-current={page === 'workspace' ? 'page' : undefined}>Workspace</a><a href="#vaults" aria-current={page === 'vaults' ? 'page' : undefined}>Vaults</a><a href="#access" aria-current={page === 'access' ? 'page' : undefined}>Access & Rotations</a><a href="#roadmap" aria-current={page === 'roadmap' ? 'page' : undefined}>Roadmap</a></nav><div className="session-badge">{session.authenticated ? <><span className="badge" data-testid="signed-in-user">{session.user?.email}</span><button type="button" className="badge" onClick={() => void signOut()} data-testid="sign-out">Sign out</button></> : <a className="badge" href="/api/v1/auth/login?return_to=/">Sign in</a>}</div></header>
    <main id="content" tabIndex={-1}>
      <div className="eyebrow">{project.mode.replaceAll('-', ' ')} · browser workspace</div>
      <h1>{page === 'workspace' ? project.title : page === 'vaults' ? 'Authorized secret metadata console.' : page === 'access' ? 'Provider operations and access control.' : 'A clear path to release.'}</h1>
      <p className="intro">{page === 'workspace' ? project.description : page === 'vaults' ? 'Explore encrypted secret metadata without fetching or persisting plaintext values (Requirement F14).' : page === 'access' ? 'Audit provider access grants and track resumable rotation states. Partial failures are explicitly visible (Requirement F16).' : 'Track the product plan separately from the web foundation. Each task includes an acceptance target.'}</p>
      {page === 'workspace' ? <>
        <section className="notice" aria-label="Availability" aria-live="polite"><span className="dot"/>{engine} {coreReady ? 'Domain processing is enabled for this local workspace.' : 'Domain processing is unavailable; this release does not produce security results.'}</section>
        <div className="grid"><section className="panel"><div className="eyebrow">Local file preview</div><h2>Inspect a document</h2><p>Choose a JSON file to inspect its top-level fields. The file stays in memory in this tab and is not uploaded or saved.</p><label className="file-button">Choose JSON file<input aria-label="Choose JSON file" type="file" accept=".json,application/json" onChange={event => { void importFile(event.target.files?.[0]); event.target.value = ''; }}/></label><p className="muted">Maximum {Math.round(config.maxPreviewBytes / 1024)} KiB · JSON structure only</p>
          {error && <p role="alert" className="error">{error}</p>}
          {preview && <div className="preview" role="status"><h3>{preview.name}</h3><p>{preview.bytes} bytes · {preview.fields.length} top-level fields</p><ul>{preview.fields.slice(0, 30).map(field => <li key={field}><code>{field}</code></li>)}</ul><p className="muted">JSON structure checked. Domain validation requires the engine.</p><button onClick={() => { generation.current++; setPreview(null); }}>Clear preview</button></div>}
        </section><section className="panel"><div className="eyebrow">Product contract</div><h2>{project.documentType.replaceAll('-', ' ')}</h2><p>The engine will enforce these domain guarantees.</p><ul className="invariants">{project.invariants.map(invariant => <li key={invariant}>{invariant}</li>)}</ul><a className="text-link" href="#roadmap">Explore the implementation plan <span aria-hidden="true">→</span></a></section></div>
        <section className="panel"><div className="eyebrow">Web foundation</div><h2>Release preparation</h2><div className="milestones">{project.webTasks.map(task => <article key={task.id}><span className="task-id">{task.id}</span><h3>{task.title}</h3><span className={'state ' + task.status}>{task.status.replaceAll('_', ' ')}</span></article>)}</div></section>
      </> : page === 'vaults' ? <section className="panel"><Vaults vaultId="vault-prod" /></section> : page === 'access' ? <section className="panel"><Access vaultId="vault-prod" /></section> : <section className="panel"><div className="filters"><label>Search tasks<input value={query} onChange={event => setQuery(event.target.value)} placeholder="ID or task title" type="search"/></label><label>Stage<select value={stage} onChange={event => setStage(event.target.value)}><option value="all">All stages</option>{[...new Set(project.tasks.map(task => task.stage))].map(value => <option key={value} value={value}>{value}</option>)}</select></label></div><p aria-live="polite" className="muted">{tasks.length} of {project.tasks.length} product tasks</p><ol className="tasks">{tasks.map(task => <li key={task.id}><div className="task-line"><span className="task-id">{task.id}</span><h2>{task.title}</h2><span className="state">{task.status.replaceAll('_', ' ')}</span></div><p>{task.acceptance.join(' ')}</p><p className="muted">Stage: {task.stage} · Prerequisites: {task.dependsOn.join(', ') || 'None'}</p></li>)}</ol>{tasks.length === 0 && <p>No matching tasks.</p>}</section>}
    </main><footer><span>{project.name}</span><span>No telemetry · No automatic file uploads</span></footer>
  </div>;
}

const root = createRoot(document.getElementById('root')!);
fetch('/runtime-config.json', { cache: 'no-store', credentials: 'omit' }).then(async response => {
  if (!response.ok) throw new Error('Workspace configuration is unavailable.');
  return validateRuntimeConfig(await response.json(), project.slug) as Runtime;
}).then(config => root.render(<StrictMode><App config={config}/></StrictMode>)).catch(() => {
  root.render(<main className="startup-error"><h1>Workspace unavailable</h1><p>The workspace configuration could not be loaded. Reload the page or contact the operator.</p></main>);
});
