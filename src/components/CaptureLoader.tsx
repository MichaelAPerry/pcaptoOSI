import { useCallback, useRef, useState } from 'react';
import { SAMPLE_CAPTURES, decodeSample, type SampleCapture } from '../data/samples';

interface Props {
  onLoadFile: (file: File) => void;
  onLoadSample: (sample: SampleCapture) => void;
  compact?: boolean;
  error?: string | null;
}

/**
 * The welcome screen: a drop target plus the bundled lab captures.
 *
 * The sample library exists so a student with no capture file of their own --
 * which is most of them, since capturing traffic usually needs admin rights --
 * can start learning in one click.
 */
export function CaptureLoader({ onLoadFile, onLoadSample, compact = false, error }: Props) {
  const [dragging, setDragging] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files?.[0];
      if (file) onLoadFile(file);
    },
    [onLoadFile],
  );

  return (
    <div className={compact ? 'p-4' : 'mx-auto w-full max-w-5xl px-6 py-10'}>
      {!compact && (
        <header className="mb-8 text-center">
          <h1 className="text-2xl font-semibold tracking-tight">PCAP-to-OSI Interactive Visualizer</h1>
          <p className="mx-auto mt-2 max-w-2xl text-[13px] leading-relaxed dim">
            Drop a packet capture and watch it come apart into the seven OSI layers, byte by byte. Every header field
            comes with a plain-English explanation of what it does and why its value matters here.
          </p>
          <p className="mt-2 text-[12px] faint">
            Everything runs inside this browser tab. No upload, no server, no network access — open the page once and it
            works offline for the rest of the lesson.
          </p>
        </header>
      )}

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-xl border-2 border-dashed px-6 text-center transition-colors focus-ring ${
          compact ? 'py-6' : 'py-12'
        } ${dragging ? 'border-[var(--accent)] bg-[var(--bg-hover)]' : 'hairline hover:border-[var(--border-strong)]'}`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap,.dmp,application/vnd.tcpdump.pcap"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onLoadFile(file);
            e.target.value = '';
          }}
        />
        <p className="text-[14px] font-medium">Drop a .pcap or .pcapng file here</p>
        <p className="mt-1 text-[12px] faint">or click to browse — the file is read locally and never leaves this machine</p>
      </div>

      {error && (
        <p className="mt-3 rounded-lg border px-3 py-2 text-[12px]" style={{ borderColor: '#f2724f', color: '#f2724f' }}>
          {error}
        </p>
      )}

      <div className="mt-8">
        <h2 className="mb-1 text-[12px] font-semibold tracking-wide uppercase dim">Built-in lab captures</h2>
        <p className="mb-3 text-[11.5px] faint">
          Synthetic captures built byte by byte from the RFCs — real checksums, real sequence numbers, no real people's
          traffic. They open in Wireshark too.
        </p>

        <div className="grid gap-2 sm:grid-cols-2">
          {SAMPLE_CAPTURES.map((sample) => (
            <div key={sample.id} className="panel overflow-hidden">
              <button
                onClick={() => onLoadSample(sample)}
                className="w-full px-3 py-2.5 text-left transition-colors hover:bg-[var(--bg-hover)] focus-ring"
              >
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[13px] font-semibold">{sample.title}</span>
                  <span className="mono shrink-0 rounded px-1.5 py-0.5 text-[10px] surface dim">{sample.layers}</span>
                </div>
                <p className="mt-1 text-[11.5px] leading-relaxed dim">{sample.blurb}</p>
                <p className="mono mt-1.5 text-[10.5px] faint">
                  {sample.fileName} · {sample.byteLength} bytes · {sample.format}
                </p>
              </button>
              <button
                onClick={() => setExpanded(expanded === sample.id ? null : sample.id)}
                className="w-full border-t px-3 py-1.5 text-left text-[11px] transition-colors hairline faint hover:bg-[var(--bg-hover)] focus-ring"
              >
                {expanded === sample.id ? '− Hide' : '+ Show'} what this capture teaches
              </button>
              {expanded === sample.id && (
                <ul className="animate-in space-y-1 border-t px-3 py-2 hairline">
                  {sample.teaches.map((t) => (
                    <li key={t} className="flex gap-1.5 text-[11.5px] leading-relaxed dim">
                      <span className="faint">•</span>
                      <span>{t}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      </div>

      {!compact && (
        <p className="mt-8 text-center text-[11px] leading-relaxed faint">
          Supported: classic libpcap (all four magic-number variants) and pcapng. Link types: Ethernet, 802.1Q VLAN,
          raw IPv4/IPv6, Linux cooked capture (SLL and SLL2) and BSD loopback. Compressed <span className="mono">.pcap.gz</span>{' '}
          files must be decompressed first.
        </p>
      )}
    </div>
  );
}

export type { SampleCapture };
export { SAMPLE_CAPTURES, decodeSample };
