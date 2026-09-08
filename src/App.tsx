import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Capture, DissectedPacket, Field } from './pcap/types';
import { loadCapture, filterPackets, protocolCounts, CaptureParseError } from './pcap/capture';
import { buildEncapsulation, buildLayerViews } from './pcap/osi';
import type { Highlight } from './lib/highlight';
import { PacketTable, protocolLayer } from './components/PacketTable';
import { HexView } from './components/HexView';
import { OsiInspector } from './components/OsiInspector';
import { EncapsulationDiagram } from './components/EncapsulationDiagram';
import { FieldDrawer } from './components/FieldDrawer';
import { CaptureLoader } from './components/CaptureLoader';
import { decodeSample, type SampleCapture } from './data/samples';

type RightTab = 'osi' | 'encap';

export function App() {
  const [capture, setCapture] = useState<Capture | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [filter, setFilter] = useState('');
  const [highlight, setHighlight] = useState<Highlight | null>(null);
  const [selectedField, setSelectedField] = useState<Field | null>(null);
  const [encapMode, setEncapMode] = useState<'tx' | 'rx'>('tx');
  const [rightTab, setRightTab] = useState<RightTab>('osi');
  const [teacherMode, setTeacherMode] = useState(true);
  // Dark-first by design, but follow the host's stated preference on first
  // paint so the tool does not fight the environment it is embedded in.
  const [light, setLight] = useState(() => {
    if (typeof document === 'undefined') return false;
    const stamped = document.documentElement.dataset.theme;
    if (stamped === 'light') return true;
    if (stamped === 'dark') return false;
    return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches;
  });
  const [showLoader, setShowLoader] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle('light', light);
  }, [light]);

  const ingest = useCallback((fileName: string, buffer: ArrayBuffer) => {
    setBusy(true);
    setError(null);
    try {
      const result = loadCapture(fileName, buffer);
      if (result.packets.length === 0) {
        setError(`${fileName} parsed correctly but contains no packets.`);
        setBusy(false);
        return;
      }
      setCapture(result);
      setSelectedIndex(result.packets[0].index);
      setSelectedField(null);
      setHighlight(null);
      setFilter('');
      setShowLoader(false);
    } catch (e) {
      setError(
        e instanceof CaptureParseError
          ? e.message
          : `Could not read ${fileName}: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setBusy(false);
    }
  }, []);

  const handleFile = useCallback(
    (file: File) => {
      setBusy(true);
      file
        .arrayBuffer()
        .then((buffer) => ingest(file.name, buffer))
        .catch((e) => {
          setError(`Could not read ${file.name}: ${e instanceof Error ? e.message : String(e)}`);
          setBusy(false);
        });
    },
    [ingest],
  );

  const handleSample = useCallback(
    (sample: SampleCapture) => ingest(sample.fileName, decodeSample(sample)),
    [ingest],
  );

  const filtered = useMemo(
    () => (capture ? filterPackets(capture.packets, filter) : []),
    [capture, filter],
  );

  const selected: DissectedPacket | null = useMemo(() => {
    if (!capture || selectedIndex === null) return null;
    return capture.packets.find((p) => p.index === selectedIndex) ?? null;
  }, [capture, selectedIndex]);

  const layers = useMemo(() => (selected ? buildLayerViews(selected) : []), [selected]);
  const boxes = useMemo(() => (selected ? buildEncapsulation(selected) : []), [selected]);
  const protocols = useMemo(() => (capture ? protocolCounts(capture.packets) : []), [capture]);

  // Arrow keys walk the (filtered) packet list; "/" jumps to the filter box.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const typing = target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA';
      if (e.key === '/' && !typing) {
        e.preventDefault();
        document.getElementById('filter-input')?.focus();
        return;
      }
      if (e.key === 'Escape') {
        if (typing) (target as HTMLInputElement).blur();
        else setSelectedField(null);
        return;
      }
      if (typing || !filtered.length) return;
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      const position = filtered.findIndex((p) => p.index === selectedIndex);
      const next = e.key === 'ArrowDown' ? Math.min(filtered.length - 1, position + 1) : Math.max(0, position - 1);
      const packet = filtered[position < 0 ? 0 : next];
      if (packet) {
        setSelectedIndex(packet.index);
        setSelectedField(null);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [filtered, selectedIndex]);

  if (!capture || showLoader) {
    return (
      <div className="min-h-full overflow-auto">
        {capture && (
          <div className="flex items-center justify-between border-b px-4 py-2 hairline">
            <span className="text-[12px] dim">Load a different capture</span>
            <button
              onClick={() => setShowLoader(false)}
              className="rounded border px-2 py-1 text-[11px] hairline dim hover:bg-[var(--bg-hover)] focus-ring"
            >
              Back to {capture.fileName}
            </button>
          </div>
        )}
        <CaptureLoader onLoadFile={handleFile} onLoadSample={handleSample} error={error} />
        {busy && <p className="pb-6 text-center text-[12px] faint">Parsing…</p>}
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b px-3 py-2 hairline">
        <h1 className="text-[13px] font-semibold whitespace-nowrap">
          PCAP<span className="faint"> → </span>OSI
        </h1>

        <div className="flex min-w-0 items-baseline gap-2">
          <span className="mono truncate text-[12px] dim" title={capture.fileName}>
            {capture.fileName}
          </span>
          <span className="whitespace-nowrap text-[11px] faint">
            {capture.meta.format} · {capture.meta.linkTypeName} · {capture.packets.length} frames ·{' '}
            {(capture.fileSize / 1024).toFixed(1)} KiB
          </span>
        </div>

        <div className="ml-auto flex flex-1 items-center gap-2 sm:flex-none">
          <div className="relative min-w-[200px] flex-1 sm:w-[300px] sm:flex-none">
            <input
              id="filter-input"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter — try tcp, port:443, src:192.168.1.42, -arp"
              className="w-full rounded-md border px-2.5 py-1 text-[12px] hairline focus-ring"
              style={{ background: 'var(--bg-raised)' }}
            />
            {filter && (
              <button
                onClick={() => setFilter('')}
                className="absolute top-1/2 right-1.5 -translate-y-1/2 rounded px-1 text-[13px] leading-none faint hover:text-[var(--text)] focus-ring"
                aria-label="Clear filter"
              >
                ×
              </button>
            )}
          </div>

          <button
            onClick={() => setTeacherMode((v) => !v)}
            title="Show plain-English explanations inline as you hover fields"
            className={`rounded-md border px-2 py-1 text-[11px] whitespace-nowrap transition-colors focus-ring ${
              teacherMode ? 'border-[var(--accent)] text-[var(--accent)]' : 'hairline faint'
            }`}
          >
            Teacher mode {teacherMode ? 'on' : 'off'}
          </button>

          <button
            onClick={() => setLight((v) => !v)}
            className="rounded-md border px-2 py-1 text-[11px] hairline dim hover:bg-[var(--bg-hover)] focus-ring"
            aria-label="Toggle theme"
          >
            {light ? '☾' : '☀'}
          </button>

          <button
            onClick={() => setShowLoader(true)}
            className="rounded-md border px-2 py-1 text-[11px] whitespace-nowrap hairline dim hover:bg-[var(--bg-hover)] focus-ring"
          >
            Open capture
          </button>
        </div>
      </header>

      {protocols.length > 1 && (
        <div className="flex flex-wrap items-center gap-1.5 border-b px-3 py-1.5 hairline">
          <button
            onClick={() => setFilter('')}
            className={`rounded px-1.5 py-0.5 text-[11px] transition-colors focus-ring ${
              filter === '' ? 'bg-[var(--bg-hover)] text-[var(--text)]' : 'faint hover:text-[var(--text-dim)]'
            }`}
          >
            All ({capture.packets.length})
          </button>
          {protocols.map((p) => (
            <button
              key={p.name}
              data-layer={protocolLayer(p.name)}
              onClick={() => setFilter(filter === `proto:${p.name.toLowerCase()}` ? '' : `proto:${p.name.toLowerCase()}`)}
              className={`rounded px-1.5 py-0.5 text-[11px] font-medium transition-colors focus-ring ${
                filter === `proto:${p.name.toLowerCase()}` ? 'layer-bg layer-text' : 'faint hover:layer-text'
              }`}
            >
              {p.name} ({p.count})
            </button>
          ))}
          {capture.warnings.length > 0 && (
            <span className="ml-auto text-[11px]" style={{ color: '#f0a848' }} title={capture.warnings.join('\n')}>
              ⚠ {capture.warnings.length} file warning{capture.warnings.length === 1 ? '' : 's'}
            </span>
          )}
        </div>
      )}

      <main className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="min-h-0 flex-[4] border-b hairline">
            <PacketTable
              packets={filtered}
              totalCount={capture.packets.length}
              selectedIndex={selectedIndex}
              onSelect={(p) => {
                setSelectedIndex(p.index);
                setSelectedField(null);
              }}
            />
          </div>
          <div className="min-h-0 flex-[5]">
            {selected && (
              <HexView
                packet={selected}
                layers={layers}
                highlight={highlight}
                onHighlight={setHighlight}
                onSelectField={setSelectedField}
              />
            )}
          </div>
        </div>

        <aside className="flex min-h-0 w-full shrink-0 flex-col border-t lg:w-[470px] lg:border-t-0 lg:border-l hairline">
          <div className="flex shrink-0 border-b hairline">
            {(
              [
                ['osi', 'OSI layers'],
                ['encap', 'Encapsulation'],
              ] as Array<[RightTab, string]>
            ).map(([id, label]) => (
              <button
                key={id}
                onClick={() => setRightTab(id)}
                className={`flex-1 border-b-2 px-3 py-2 text-[12px] font-medium transition-colors focus-ring ${
                  rightTab === id
                    ? 'border-[var(--accent)] text-[var(--text)]'
                    : 'border-transparent faint hover:text-[var(--text-dim)]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="min-h-0 flex-1">
            {selected && rightTab === 'osi' && (
              <OsiInspector
                packet={selected}
                layers={layers}
                highlight={highlight}
                onHighlight={setHighlight}
                selectedField={selectedField}
                onSelectField={setSelectedField}
                teacherMode={teacherMode}
              />
            )}
            {selected && rightTab === 'encap' && (
              <EncapsulationDiagram
                packet={selected}
                boxes={boxes}
                mode={encapMode}
                onModeChange={setEncapMode}
                highlight={highlight}
                onHighlight={setHighlight}
              />
            )}
          </div>

          {selected && (
            <>
              {selected.warnings.length > 0 && (
                <div className="border-t px-3 py-1.5 text-[11px] hairline" style={{ color: '#f0a848' }}>
                  {selected.warnings.map((w) => (
                    <p key={w}>⚠ {w}</p>
                  ))}
                </div>
              )}
              <FieldDrawer field={selectedField} bytes={selected.bytes} onClose={() => setSelectedField(null)} />
            </>
          )}
        </aside>
      </main>
    </div>
  );
}
