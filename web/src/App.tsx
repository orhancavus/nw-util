import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Archive,
  ChevronRight,
  CircleStop,
  Clock3,
  Download,
  Gauge,
  History,
  Laptop,
  Menu,
  Moon,
  Network,
  Play,
  Radar,
  RefreshCw,
  Search,
  ServerCog,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Tag,
  Wifi,
  X,
  Zap,
} from 'lucide-react';
import { api } from './lib/api';
import type {
  Capabilities,
  Device,
  HistoryRecord,
  Job,
  NetworkContext,
  ScanResult,
  ScanSettings,
  SecurityProfile,
  WatchEvent,
} from './types';

type View = 'devices' | 'watch' | 'history';
type Theme = 'dark' | 'light';

const initialSettings: ScanSettings = {
  network: null,
  timeout: 0.5,
  workers: 64,
  max_hosts: 1024,
  deep: false,
  discover: true,
  mdns_timeout: 2,
  record_history: true,
};

const phaseLabels: Record<string, string> = {
  queued: 'Queued',
  detecting_network: 'Detecting network',
  probing_hosts: 'Probing hosts',
  discovering_mdns: 'Discovering services',
  enriching_services: 'Inspecting services',
  saving_history: 'Saving history',
  resolving_target: 'Resolving device',
  inspecting_services: 'Inspecting services',
  cancelling: 'Stopping',
  complete: 'Complete',
};

function App() {
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = window.localStorage.getItem('nw-util-theme');
    if (saved === 'dark' || saved === 'light') return saved;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  });
  const [view, setView] = useState<View>('devices');
  const [context, setContext] = useState<NetworkContext | null>(null);
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [settings, setSettings] = useState(initialSettings);
  const [scanJob, setScanJob] = useState<Job<ScanResult> | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [phase, setPhase] = useState('standby');
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sort, setSort] = useState<'ip' | 'name' | 'latency'>('ip');
  const [selected, setSelected] = useState<Device | null>(null);
  const [dockOpen, setDockOpen] = useState(() => window.matchMedia('(min-width: 1051px)').matches);
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [watchJob, setWatchJob] = useState<Job<ScanResult> | null>(null);
  const [watchEvents, setWatchEvents] = useState<WatchEvent[]>([]);
  const scanSource = useRef<EventSource | null>(null);
  const watchSource = useRef<EventSource | null>(null);

  useEffect(() => {
    document.documentElement.classList.toggle('light-theme', theme === 'light');
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.documentElement.style.colorScheme = theme;
    window.localStorage.setItem('nw-util-theme', theme);
  }, [theme]);

  useEffect(() => {
    const desktop = window.matchMedia('(min-width: 1051px)');
    const syncDockToViewport = (event: MediaQueryListEvent) => setDockOpen(event.matches);
    desktop.addEventListener('change', syncDockToViewport);
    return () => desktop.removeEventListener('change', syncDockToViewport);
  }, []);

  useEffect(() => {
    Promise.all([api.context(), api.capabilities()])
      .then(([nextContext, nextCapabilities]) => {
        setContext(nextContext);
        setCapabilities(nextCapabilities);
        setSettings((current) => ({ ...current, network: nextContext.network }));
      })
      .catch((reason: Error) => setError(reason.message));
    return () => {
      scanSource.current?.close();
      watchSource.current?.close();
    };
  }, []);

  useEffect(() => {
    if (view !== 'history') return;
    setHistoryLoading(true);
    api
      .history(query)
      .then((response) => setHistory(response.records))
      .catch((reason: Error) => setError(reason.message))
      .finally(() => setHistoryLoading(false));
  }, [view, query]);

  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setSelected(null);
        setDockOpen(false);
      }
      if (event.key.toLowerCase() === 's' && !['INPUT', 'TEXTAREA', 'SELECT'].includes((event.target as HTMLElement).tagName)) {
        event.preventDefault();
        if (!scanJob || !['queued', 'running', 'cancelling'].includes(scanJob.status)) void startScan();
      }
      if (event.key === '/' && !['INPUT', 'TEXTAREA'].includes((event.target as HTMLElement).tagName)) {
        event.preventDefault();
        document.getElementById('device-search')?.focus();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  });

  const filteredDevices = useMemo(() => {
    const devices = [...(scanResult?.devices ?? [])];
    return devices
      .filter((device) => {
        const haystack = [device.name, device.type, device.status, device.ip, device.mac, device.vendor, ...device.services]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return (
          (!query || haystack.includes(query.toLowerCase())) &&
          (typeFilter === 'all' || device.type === typeFilter) &&
          (statusFilter === 'all' || (statusFilter === 'online' ? device.responsive : !device.responsive))
        );
      })
      .sort((a, b) => {
        if (sort === 'name') return a.name.localeCompare(b.name);
        if (sort === 'latency') return (a.latency_ms ?? Infinity) - (b.latency_ms ?? Infinity);
        return a.ip.localeCompare(b.ip, undefined, { numeric: true });
      });
  }, [query, scanResult, sort, statusFilter, typeFilter]);

  const deviceTypes = useMemo(
    () => Array.from(new Set((scanResult?.devices ?? []).map((device) => device.type))).sort(),
    [scanResult],
  );

  const scanActive = Boolean(scanJob && ['queued', 'running', 'cancelling'].includes(scanJob.status));
  const watchActive = Boolean(watchJob && ['queued', 'running', 'cancelling'].includes(watchJob.status));
  const onlineCount = scanResult?.devices.filter((device) => device.responsive).length ?? 0;

  async function startScan() {
    setError(null);
    setPhase('queued');
    setView('devices');
    try {
      const job = await api.createScan(settings);
      setScanJob(job as Job<ScanResult>);
      const source = new EventSource(api.eventUrl('scans', job.id));
      scanSource.current?.close();
      scanSource.current = source;
      source.addEventListener('state', () => setScanJob((current) => (current ? { ...current, status: 'running' } : current)));
      source.addEventListener('progress', (event) => {
        const payload = JSON.parse((event as MessageEvent).data);
        setPhase(payload.phase);
      });
      source.addEventListener('complete', (event) => {
        const payload = JSON.parse((event as MessageEvent).data);
        setScanResult(payload.result);
        setScanJob((current) => (current ? { ...current, status: 'completed', result: payload.result } : current));
        setPhase('complete');
        source.close();
      });
      source.addEventListener('error', (event) => {
        if (event instanceof MessageEvent && event.data) {
          const payload = JSON.parse(event.data);
          setError(payload.message ?? 'Scan failed');
          setScanJob((current) => (current ? { ...current, status: 'failed' } : current));
        }
        source.close();
      });
      source.addEventListener('cancelled', () => {
        setPhase('standby');
        setScanJob((current) => (current ? { ...current, status: 'cancelled' } : current));
        source.close();
      });
    } catch (reason) {
      setError((reason as Error).message);
      setPhase('standby');
    }
  }

  async function cancelScan() {
    if (!scanJob) return;
    setPhase('cancelling');
    try {
      const job = await api.cancelScan(scanJob.id);
      setScanJob(job as Job<ScanResult>);
    } catch (reason) {
      setError((reason as Error).message);
    }
  }

  async function startWatch() {
    setError(null);
    setWatchEvents([]);
    try {
      const job = await api.createWatch(settings, 10);
      setWatchJob(job as Job<ScanResult>);
      setView('watch');
      const source = new EventSource(api.eventUrl('watches', job.id));
      watchSource.current?.close();
      watchSource.current = source;
      source.addEventListener('state', () => setWatchJob((current) => (current ? { ...current, status: 'running' } : current)));
      source.addEventListener('snapshot', (event) => {
        const payload = JSON.parse((event as MessageEvent).data);
        setScanResult(payload.result);
      });
      source.addEventListener('device_change', (event) => {
        const payload = JSON.parse((event as MessageEvent).data);
        setWatchEvents((current) => [payload, ...current].slice(0, 250));
      });
      source.addEventListener('error', (event) => {
        if (event instanceof MessageEvent && event.data) setError(JSON.parse(event.data).message ?? 'Watch failed');
      });
      source.addEventListener('cancelled', () => {
        setWatchJob((current) => (current ? { ...current, status: 'cancelled' } : current));
        source.close();
      });
    } catch (reason) {
      setError((reason as Error).message);
    }
  }

  async function stopWatch() {
    if (!watchJob) return;
    try {
      const job = await api.stopWatch(watchJob.id);
      setWatchJob(job as Job<ScanResult>);
    } catch (reason) {
      setError((reason as Error).message);
    }
  }

  function patchDevice(ip: string, alias: string | null) {
    setScanResult((current) =>
      current
        ? {
            ...current,
            devices: current.devices.map((device) =>
              device.ip === ip ? { ...device, alias, name: alias || device.hostname || device.model || device.vendor || 'Unknown' } : device,
            ),
          }
        : current,
    );
    setSelected((current) =>
      current?.ip === ip ? { ...current, alias, name: alias || current.hostname || current.model || current.vendor || 'Unknown' } : current,
    );
  }

  return (
    <div className="app-shell">
      <Header
        context={context}
        capabilities={capabilities}
        scanActive={scanActive}
        watchActive={watchActive}
        phase={phase}
        total={scanResult?.device_count ?? 0}
        online={onlineCount}
        theme={theme}
        dockOpen={dockOpen}
        onToggleTheme={() => setTheme((current) => current === 'dark' ? 'light' : 'dark')}
        onToggleDock={() => setDockOpen((open) => !open)}
      />

      <nav className="view-tabs" aria-label="Primary navigation">
        <ViewTab active={view === 'devices'} icon={<Radar />} label="Devices" onClick={() => setView('devices')} />
        <ViewTab active={view === 'watch'} icon={<Activity />} label="Live watch" badge={watchActive ? 'LIVE' : undefined} onClick={() => setView('watch')} />
        <ViewTab active={view === 'history'} icon={<History />} label="History" onClick={() => setView('history')} />
      </nav>

      {error && (
        <div className="error-banner" role="alert">
          <AlertTriangle size={16} />
          <span>{error}</span>
          <button onClick={() => setError(null)} aria-label="Dismiss error"><X size={16} /></button>
        </div>
      )}

      <main className="workspace">
        <section className="canvas-panel">
          {view === 'devices' && (
            <DevicesView
              devices={filteredDevices}
              allCount={scanResult?.device_count ?? 0}
              loading={scanActive}
              phase={phase}
              hasScanned={Boolean(scanResult)}
              query={query}
              setQuery={setQuery}
              selected={selected}
              setSelected={setSelected}
              onScan={startScan}
            />
          )}
          {view === 'watch' && (
            <WatchView active={watchActive} events={watchEvents} devices={scanResult?.devices ?? []} onStart={startWatch} onStop={stopWatch} onSelect={setSelected} />
          )}
          {view === 'history' && <HistoryView loading={historyLoading} records={history} />}
        </section>

        <ControlDock
          open={dockOpen}
          settings={settings}
          setSettings={setSettings}
          query={query}
          setQuery={setQuery}
          typeFilter={typeFilter}
          setTypeFilter={setTypeFilter}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          sort={sort}
          setSort={setSort}
          deviceTypes={deviceTypes}
          capabilities={capabilities}
          onClose={() => setDockOpen(false)}
        />
      </main>

      <ActionBar
        scanActive={scanActive}
        watchActive={watchActive}
        scanId={scanJob?.status === 'completed' ? scanJob.id : null}
        onScan={startScan}
        onCancel={cancelScan}
        onWatch={watchActive ? stopWatch : startWatch}
        onOpenFilters={() => setDockOpen(true)}
      />

      {selected && <DeviceInspector device={selected} onClose={() => setSelected(null)} onPatch={patchDevice} />}
      <div className="sr-only" aria-live="polite">{scanActive ? phaseLabels[phase] ?? phase : ''}</div>
    </div>
  );
}

function Header(props: {
  context: NetworkContext | null;
  capabilities: Capabilities | null;
  scanActive: boolean;
  watchActive: boolean;
  phase: string;
  total: number;
  online: number;
  theme: Theme;
  dockOpen: boolean;
  onToggleTheme: () => void;
  onToggleDock: () => void;
}) {
  const state = props.watchActive ? 'WATCHING' : props.scanActive ? 'SCANNING' : 'STANDBY';
  return (
    <header className="top-hud">
      <div className="brand-block">
        <div className="brand-mark"><Network size={21} /></div>
        <div><strong>nw-util</strong><span>NETWORK CONSOLE</span></div>
        <span className="pro-badge">LOCAL</span>
      </div>
      <div className="telemetry-pill" aria-label={`System ${state}`}>
        <span className={`status-dot ${props.scanActive || props.watchActive ? 'pulse' : ''}`} />
        <strong>{state}</strong>
        <i />
        <span>{props.context?.network ?? 'DETECTING…'}</span>
        <i />
        <span className="accent">{props.online}/{props.total} ONLINE</span>
        {props.scanActive && <><i /><span>{phaseLabels[props.phase] ?? props.phase}</span></>}
      </div>
      <div className="hud-actions">
        <a
          href="https://github.com/orhancavus"
          target="_blank"
          rel="noopener noreferrer"
          aria-label="GitHub Profile (@orhancavus)"
          title="GitHub — @orhancavus"
          className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-amber-400 hover:border-zinc-700 transition-colors flex items-center gap-1.5"
        >
          <svg
            viewBox="0 0 24 24"
            fill="currentColor"
            className="w-4 h-4"
            aria-hidden="true"
          >
            <path
              fillRule="evenodd"
              clipRule="evenodd"
              d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
            />
          </svg>
        </a>
        <button
          type="button"
          className="theme-toggle"
          onClick={props.onToggleTheme}
          aria-label={`Switch to ${props.theme === 'dark' ? 'light' : 'dark'} theme`}
          aria-pressed={props.theme === 'light'}
          title={`Switch to ${props.theme === 'dark' ? 'light' : 'dark'} theme`}
        >
          {props.theme === 'dark' ? <Sun size={17} aria-hidden="true" /> : <Moon size={17} aria-hidden="true" />}
        </button>
        <span className={`capability ${props.capabilities?.nmap ? 'ready' : ''}`} title="Nmap deep-scan capability">
          <Zap size={13} /> NMAP {props.capabilities?.nmap ? 'READY' : 'OFF'}
        </span>
        <button
          type="button"
          onClick={props.onToggleDock}
          aria-label={`${props.dockOpen ? 'Hide' : 'Show'} scan parameters`}
          aria-expanded={props.dockOpen}
          aria-controls="scan-parameters-dock"
          title={`${props.dockOpen ? 'Hide' : 'Show'} scan parameters`}
        >
          <SlidersHorizontal size={19} />
        </button>
      </div>
    </header>
  );
}

function ViewTab({ active, icon, label, badge, onClick }: { active: boolean; icon: React.ReactNode; label: string; badge?: string; onClick: () => void }) {
  return <button className={active ? 'active' : ''} onClick={onClick}>{icon}<span>{label}</span>{badge && <em>{badge}</em>}</button>;
}

function DevicesView(props: {
  devices: Device[];
  allCount: number;
  loading: boolean;
  phase: string;
  hasScanned: boolean;
  query: string;
  setQuery: (value: string) => void;
  selected: Device | null;
  setSelected: (device: Device) => void;
  onScan: () => void;
}) {
  return (
    <div className="content-frame">
      <div className="canvas-heading">
        <div><span className="eyebrow">LIVE INVENTORY</span><h1>Local network devices</h1></div>
        <div className="search-box"><Search size={15} /><input id="device-search" value={props.query} onChange={(event) => props.setQuery(event.target.value)} placeholder="Search name, IP, vendor…" /></div>
      </div>
      {props.loading && !props.hasScanned ? (
        <div className="empty-state scanning"><div className="radar-sweep"><Radar /></div><span className="eyebrow">{phaseLabels[props.phase] ?? props.phase}</span><h2>Listening across the local link</h2><p>Hosts will appear when the scan completes.</p></div>
      ) : !props.hasScanned ? (
        <div className="empty-state"><div className="empty-icon"><Wifi /></div><span className="eyebrow">READY TO PROBE</span><h2>See what is on your network</h2><p>Run a bounded, read-only scan of the detected IPv4 subnet. Device data stays on this machine.</p><button className="primary-button" onClick={props.onScan}><Radar size={17} /> Scan network</button></div>
      ) : props.devices.length === 0 ? (
        <div className="empty-state compact"><Search /><h2>No matching devices</h2><p>Adjust the search or filters in the control dock.</p></div>
      ) : (
        <>
          <div className="table-summary"><span>{props.devices.length} visible</span><span>{props.allCount} discovered</span></div>
          <div className="device-table-wrap">
            <table className="device-table">
              <thead><tr><th>Device</th><th>Status</th><th>IP address</th><th>MAC address</th><th>Vendor</th><th>Services</th><th><span className="sr-only">Open</span></th></tr></thead>
              <tbody>{props.devices.map((device) => <DeviceRow key={device.id} device={device} selected={props.selected?.id === device.id} onClick={() => props.setSelected(device)} />)}</tbody>
            </table>
          </div>
          <div className="device-cards">{props.devices.map((device) => <DeviceCard key={device.id} device={device} onClick={() => props.setSelected(device)} />)}</div>
        </>
      )}
    </div>
  );
}

function DeviceRow({ device, selected, onClick }: { device: Device; selected: boolean; onClick: () => void }) {
  return (
    <tr className={selected ? 'selected' : ''} onClick={onClick} tabIndex={0} onKeyDown={(event) => event.key === 'Enter' && onClick()}>
      <td><div className="device-name"><span>{device.emoji}</span><div><strong>{device.name}</strong><small>{device.type}{device.is_self ? ' · this device' : device.is_gateway ? ' · gateway' : ''}</small></div></div></td>
      <td><StatusLabel device={device} /></td>
      <td className="mono sky">{device.ip}</td>
      <td className="mono muted">{device.mac ?? '—'}</td>
      <td>{device.vendor ?? '—'}</td>
      <td><div className="service-list">{device.services.slice(0, 2).map((service) => <span key={service}>{service}</span>)}{device.services.length > 2 && <span>+{device.services.length - 2}</span>}{device.services.length === 0 && <span className="none">—</span>}</div></td>
      <td><ChevronRight size={16} /></td>
    </tr>
  );
}

function DeviceCard({ device, onClick }: { device: Device; onClick: () => void }) {
  return <button className="device-card" onClick={onClick}><span className="device-emoji">{device.emoji}</span><div><strong>{device.name}</strong><small>{device.type}</small><span className="mono sky">{device.ip}</span></div><StatusLabel device={device} /><ChevronRight /></button>;
}

function StatusLabel({ device }: { device: Device }) {
  return <span className={`status-label ${device.responsive ? 'online' : 'offline'}`}><span />{device.status}</span>;
}

function WatchView(props: { active: boolean; events: WatchEvent[]; devices: Device[]; onStart: () => void; onStop: () => void; onSelect: (device: Device) => void }) {
  return (
    <div className="content-frame">
      <div className="canvas-heading"><div><span className="eyebrow">CHANGE TELEMETRY</span><h1>Live network watch</h1></div><button className={props.active ? 'danger-button' : 'secondary-button'} onClick={props.active ? props.onStop : props.onStart}>{props.active ? <CircleStop /> : <Play />}{props.active ? 'Stop watch' : 'Start watch'}</button></div>
      {!props.active && props.events.length === 0 ? <div className="empty-state"><div className="empty-icon"><Activity /></div><span className="eyebrow">EVENT MONITOR</span><h2>Track joins and departures</h2><p>Watch mode periodically scans and reports new, online, offline, and changed devices.</p></div> : (
        <div className="watch-grid">
          <section className="event-feed"><div className="section-label"><span>EVENT STREAM</span><em>{props.active ? 'CONNECTED' : 'STOPPED'}</em></div>{props.events.length === 0 ? <div className="waiting"><RefreshCw className={props.active ? 'spin-slow' : ''} />Waiting for a network change…</div> : props.events.map((event) => <button key={`${event.id}-${event.timestamp}`} onClick={() => props.onSelect(event.device)} className={`event-row ${event.change.toLowerCase()}`}><span className="event-kind">{event.change}</span><div><strong>{event.device.name}</strong><small>{event.device.ip}</small></div><time>{new Date(event.timestamp).toLocaleTimeString()}</time><ChevronRight /></button>)}</section>
          <aside className="snapshot-panel"><div className="section-label"><span>CURRENT SNAPSHOT</span><em>{props.devices.length}</em></div>{props.devices.slice(0, 12).map((device) => <button key={device.id} onClick={() => props.onSelect(device)}><span>{device.emoji}</span><div><strong>{device.name}</strong><small>{device.ip}</small></div><span className={`mini-dot ${device.responsive ? 'online' : ''}`} /></button>)}</aside>
        </div>
      )}
    </div>
  );
}

function HistoryView({ loading, records }: { loading: boolean; records: HistoryRecord[] }) {
  return <div className="content-frame"><div className="canvas-heading"><div><span className="eyebrow">PERSISTENT MEMORY</span><h1>Previously seen devices</h1></div><span className="count-chip"><Archive size={14} />{records.length} records</span></div>{loading ? <div className="empty-state compact"><RefreshCw className="spin" /><h2>Loading history</h2></div> : records.length === 0 ? <div className="empty-state"><div className="empty-icon"><History /></div><h2>No history recorded</h2><p>Completed scans appear here when history recording is enabled.</p></div> : <div className="history-list">{records.map((record) => <article key={record.id}><div className="history-icon"><Laptop /></div><div className="history-main"><strong>{record.alias || record.hostname || record.model || 'Unknown device'}</strong><small>{record.type} · {record.vendor || 'Unknown vendor'}</small><div>{record.ips.map((ip) => <span className="service-chip" key={ip}>{ip}</span>)}</div></div><div className="history-time"><small>LAST SEEN</small><time>{new Date(record.last_seen).toLocaleString()}</time><span>First {new Date(record.first_seen).toLocaleDateString()}</span></div></article>)}</div>}</div>;
}

function ControlDock(props: {
  open: boolean;
  settings: ScanSettings;
  setSettings: React.Dispatch<React.SetStateAction<ScanSettings>>;
  query: string;
  setQuery: (value: string) => void;
  typeFilter: string;
  setTypeFilter: (value: string) => void;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  sort: 'ip' | 'name' | 'latency';
  setSort: (value: 'ip' | 'name' | 'latency') => void;
  deviceTypes: string[];
  capabilities: Capabilities | null;
  onClose: () => void;
}) {
  const patch = <K extends keyof ScanSettings>(key: K, value: ScanSettings[K]) => props.setSettings((current) => ({ ...current, [key]: value }));
  return (
    <aside id="scan-parameters-dock" className={`control-dock ${props.open ? 'open' : ''}`} aria-label="Scan controls" aria-hidden={!props.open} inert={!props.open}>
      <div className="dock-title"><div><span className="eyebrow">CONTROL DOCK</span><h2>Scan parameters</h2></div><button onClick={props.onClose} aria-label="Close controls"><X /></button></div>
      <div className="dock-scroll">
        <Control label="Network range" badge="CIDR"><input value={props.settings.network ?? ''} onChange={(event) => patch('network', event.target.value || null)} className="mono" /></Control>
        <div className="control-grid"><Control label="Timeout" badge={`${props.settings.timeout}s`}><input type="range" min="0.1" max="3" step="0.1" value={props.settings.timeout} onChange={(event) => patch('timeout', Number(event.target.value))} /></Control><Control label="Workers" badge={String(props.settings.workers)}><input type="range" min="4" max="128" step="4" value={props.settings.workers} onChange={(event) => patch('workers', Number(event.target.value))} /></Control></div>
        <div className="dock-divider" />
        <span className="section-kicker">ENRICHMENT</span>
        <Toggle label="mDNS discovery" description="Local service advertisements" checked={props.settings.discover} onChange={(value) => patch('discover', value)} />
        <Toggle label="Deep service scan" description={props.capabilities?.nmap ? 'Nmap service identification' : 'Nmap is not installed'} checked={props.settings.deep} disabled={!props.capabilities?.nmap} onChange={(value) => patch('deep', value)} />
        <Toggle label="Record history" description="Save first and last seen times" checked={props.settings.record_history} onChange={(value) => patch('record_history', value)} />
        <div className="dock-divider" />
        <span className="section-kicker">RESULT FILTERS</span>
        <Control label="Search"><div className="input-icon"><Search /><input value={props.query} onChange={(event) => props.setQuery(event.target.value)} placeholder="Any field" /></div></Control>
        <Control label="Device type"><select value={props.typeFilter} onChange={(event) => props.setTypeFilter(event.target.value)}><option value="all">All types</option>{props.deviceTypes.map((type) => <option key={type}>{type}</option>)}</select></Control>
        <div className="control-grid"><Control label="Status"><select value={props.statusFilter} onChange={(event) => props.setStatusFilter(event.target.value)}><option value="all">All</option><option value="online">Online</option><option value="offline">Offline</option></select></Control><Control label="Sort"><select value={props.sort} onChange={(event) => props.setSort(event.target.value as typeof props.sort)}><option value="ip">IP address</option><option value="name">Name</option><option value="latency">Latency</option></select></Control></div>
      </div>
      <div className="privacy-note"><ShieldCheck /><div><strong>Local-only by default</strong><span>Network metadata never leaves this host.</span></div></div>
    </aside>
  );
}

function Control({ label, badge, children }: { label: string; badge?: string; children: React.ReactNode }) {
  return <label className="control"><span>{label}{badge && <em>{badge}</em>}</span>{children}</label>;
}

function Toggle({ label, description, checked, disabled, onChange }: { label: string; description: string; checked: boolean; disabled?: boolean; onChange: (value: boolean) => void }) {
  return <label className={`toggle-row ${disabled ? 'disabled' : ''}`}><div><strong>{label}</strong><span>{description}</span></div><input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} /><i /></label>;
}

function ActionBar(props: { scanActive: boolean; watchActive: boolean; scanId: string | null; onScan: () => void; onCancel: () => void; onWatch: () => void; onOpenFilters: () => void }) {
  return <footer className="action-bar"><div className="shortcut-hint"><kbd>/</kbd><span>Search</span><kbd>S</kbd><span>Scan</span></div><button className={`scan-trigger ${props.scanActive ? 'stop' : ''}`} onClick={props.scanActive ? props.onCancel : props.onScan}>{props.scanActive ? <CircleStop /> : <Radar />}<span>{props.scanActive ? 'Stop scan' : 'Scan network'}</span></button><div className="bar-actions"><button className={props.watchActive ? 'active' : ''} onClick={props.onWatch}><Activity />{props.watchActive ? 'Stop watch' : 'Watch'}</button>{props.scanId && <><a href={api.exportUrl(props.scanId, 'json')}><Download />JSON</a><a href={api.exportUrl(props.scanId, 'csv')}><Download />CSV</a></>}<button className="mobile-filter" onClick={props.onOpenFilters}><Menu />Filters</button></div></footer>;
}

function DeviceInspector({ device, onClose, onPatch }: { device: Device; onClose: () => void; onPatch: (ip: string, alias: string | null) => void }) {
  const [alias, setAlias] = useState(device.alias ?? '');
  const [profile, setProfile] = useState<SecurityProfile | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => setAlias(device.alias ?? ''), [device]);

  async function saveAlias(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (alias.trim()) {
        await api.setAlias(device.mac || device.ip, alias.trim());
        onPatch(device.ip, alias.trim());
      } else if (device.alias) {
        await api.removeAlias(device.mac || device.ip);
        onPatch(device.ip, null);
      }
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function inspect() {
    setBusy(true);
    setError(null);
    try {
      const created = await api.createSecurity(device.ip);
      for (let attempt = 0; attempt < 120; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 500));
        const job = await api.getSecurity(created.id);
        if (job.status === 'completed' && job.result) {
          setProfile(job.result);
          return;
        }
        if (job.status === 'failed') throw new Error(job.error || 'Security profile failed');
      }
      throw new Error('Security profile timed out');
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const severity = { high: 0, medium: 0, info: 0 };
  profile?.findings.forEach((finding) => { severity[finding.severity] += 1; });

  return <div className="inspector-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><aside className="inspector" role="dialog" aria-modal="true" aria-label={`Details for ${device.name}`}><header><div className="inspector-identity"><span>{device.emoji}</span><div><small>{device.type}</small><h2>{device.name}</h2></div></div><button onClick={onClose} aria-label="Close inspector"><X /></button></header><div className="inspector-scroll">
    {error && <div className="inline-error"><AlertTriangle />{error}</div>}
    <section><span className="section-kicker">IDENTITY</span><dl className="data-grid"><div><dt>IP ADDRESS</dt><dd className="sky">{device.ip}</dd></div><div><dt>MAC ADDRESS</dt><dd>{device.mac ?? 'Unknown'}</dd></div><div><dt>HOSTNAME</dt><dd>{device.hostname ?? 'Unknown'}</dd></div><div><dt>VENDOR</dt><dd>{device.vendor ?? 'Unknown'}</dd></div><div><dt>LATENCY</dt><dd>{device.latency_ms == null ? '—' : `${device.latency_ms.toFixed(1)} ms`}</dd></div><div><dt>NEIGHBOR STATE</dt><dd>{device.neighbor_state ?? '—'}</dd></div></dl></section>
    <section><span className="section-kicker">FRIENDLY NAME</span><form className="alias-form" onSubmit={saveAlias}><Tag /><input value={alias} onChange={(event) => setAlias(event.target.value)} placeholder="Add an alias" maxLength={120} /><button disabled={busy}>Save</button></form><small className="helper">Clear the field and save to remove the current alias.</small></section>
    <section><div className="section-heading"><span className="section-kicker">DISCOVERED SERVICES</span><em>{device.services.length}</em></div><div className="service-grid">{device.services.length ? device.services.map((service) => <span key={service}>{service}</span>) : <p>No advertised services were identified.</p>}</div></section>
    <section className="security-section"><div className="section-heading"><div><span className="section-kicker">SECURITY PROFILE</span><h3>Observed LAN exposure</h3></div>{profile && <div className="risk-counts"><span className="high">{severity.high} H</span><span className="medium">{severity.medium} M</span><span>{severity.info} I</span></div>}</div>{!profile ? <div className="security-empty"><ShieldCheck /><p>Inspect a bounded set of TCP services. Results are observational and do not prove a service is secure or vulnerable.</p><button onClick={inspect} disabled={busy}>{busy ? <RefreshCw className="spin" /> : <ShieldCheck />}{busy ? 'Inspecting…' : 'Run security profile'}</button></div> : <SecurityResults profile={profile} />}</section>
  </div></aside></div>;
}

function SecurityResults({ profile }: { profile: SecurityProfile }) {
  return <div className="security-results"><div className="scanner-note"><ServerCog />{profile.scanner}</div>{profile.os_detection_note && <p className="profile-note">{profile.os_detection_note}</p>}<span className="result-label">FINDINGS</span>{profile.findings.length ? profile.findings.map((finding, index) => <article className={`finding ${finding.severity}`} key={`${finding.severity}-${index}`}><AlertTriangle /><div><strong>{finding.severity}</strong><p>{finding.message}</p></div></article>) : <div className="clean-result"><ShieldCheck />No notable exposure was identified in the inspected port set.</div>}<span className="result-label">OPEN SERVICES</span>{profile.services.length ? profile.services.map((service) => <article className="open-service" key={`${service.port}-${service.protocol}`}><span className="port">{service.port}</span><div><strong>{service.name}</strong><small>{[service.product, service.version, service.extra_info].filter(Boolean).join(' ') || service.protocol.toUpperCase()}</small></div></article>) : <p className="profile-note">No inspected TCP services responded.</p>}</div>;
}

export default App;
