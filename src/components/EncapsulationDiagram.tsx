import type { DissectedPacket, OsiLayer } from '../pcap/types';
import type { EncapsulationBox } from '../pcap/osi';
import type { Highlight } from '../lib/highlight';
import { LAYER_NAMES } from '../pcap/types';

interface Props {
  packet: DissectedPacket;
  boxes: EncapsulationBox[];
  mode: 'tx' | 'rx';
  onModeChange: (mode: 'tx' | 'rx') => void;
  highlight: Highlight | null;
  onHighlight: (h: Highlight | null) => void;
}

/**
 * The encapsulation (Russian-doll) diagram.
 *
 * Same bytes, two stories. In Tx mode the numbering runs from the innermost
 * application data outwards, which is the order a sending host actually builds
 * the frame. In Rx mode it runs from the outermost frame inwards, which is the
 * order a receiving host takes it apart.
 */
export function EncapsulationDiagram({ packet, boxes, mode, onModeChange, highlight, onHighlight }: Props) {
  const innerPayload = boxes.length > 0 ? boxes[boxes.length - 1].payload : undefined;
  const steps = mode === 'tx' ? [...boxes].reverse() : boxes;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center justify-between gap-2 border-b px-3 py-2 hairline">
        <h2 className="text-[12px] font-semibold tracking-wide uppercase dim">Encapsulation</h2>
        <div className="flex rounded-md border p-0.5 hairline">
          <button
            onClick={() => onModeChange('tx')}
            className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors focus-ring ${
              mode === 'tx' ? 'bg-[var(--bg-hover)] text-[var(--text)]' : 'faint hover:text-[var(--text-dim)]'
            }`}
          >
            ↓ Encapsulate (Tx)
          </button>
          <button
            onClick={() => onModeChange('rx')}
            className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors focus-ring ${
              mode === 'rx' ? 'bg-[var(--bg-hover)] text-[var(--text)]' : 'faint hover:text-[var(--text-dim)]'
            }`}
          >
            ↑ Decapsulate (Rx)
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-3">
        <p className="mb-3 text-[11.5px] leading-relaxed dim">
          {mode === 'tx' ? (
            <>
              <span className="font-semibold text-[var(--text)]">Sending.</span> The application hands down data; each
              layer wraps it in its own header and passes it to the layer below. The frame that finally hits the wire is
              the innermost message with every wrapper around it.
            </>
          ) : (
            <>
              <span className="font-semibold text-[var(--text)]">Receiving.</span> The frame arrives as one blob of bits.
              Each layer reads its own header, checks that the message is for it, strips the header and hands the rest
              up. The application never sees any of the wrapping.
            </>
          )}
        </p>

        <NestedBoxes
          boxes={boxes}
          index={0}
          packet={packet}
          innerPayload={innerPayload}
          mode={mode}
          highlight={highlight}
          onHighlight={onHighlight}
        />

        <ol className="mt-4 space-y-1.5">
          {steps.map((box, i) => (
            <li key={`${box.id}-${i}`} data-layer={box.layer} className="flex gap-2.5">
              <span
                className="mt-[1px] flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-bold"
                style={{ background: 'var(--layer-soft)', color: 'var(--layer-color)' }}
              >
                {i + 1}
              </span>
              <p className="text-[11.5px] leading-relaxed dim">
                <span className="font-semibold layer-text">
                  L{box.layer} {LAYER_NAMES[box.layer as OsiLayer]} — {box.abbr}.{' '}
                </span>
                {mode === 'tx' ? box.encapNote : box.decapNote}
              </p>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

interface NestedProps {
  boxes: EncapsulationBox[];
  index: number;
  packet: DissectedPacket;
  innerPayload?: { offset: number; length: number };
  mode: 'tx' | 'rx';
  highlight: Highlight | null;
  onHighlight: (h: Highlight | null) => void;
}

function NestedBoxes({ boxes, index, packet, innerPayload, mode, highlight, onHighlight }: NestedProps) {
  if (index >= boxes.length) {
    if (!innerPayload || innerPayload.length === 0) {
      const innermost = boxes[boxes.length - 1];
      return (
        <div className="rounded border border-dashed px-2.5 py-2 text-center text-[11px] leading-relaxed hairline faint">
          {innermost && innermost.layer >= 5
            ? `No separate payload — the ${innermost.abbr} message itself is the data being delivered.`
            : 'No payload — this frame is pure protocol overhead, sent to run the protocol rather than to carry anything.'}
        </div>
      );
    }
    return (
      <div
        data-layer={7}
        onMouseEnter={() =>
          onHighlight({ ranges: [innerPayload], layer: 7, label: 'Application data', detail: `${innerPayload.length} bytes` })
        }
        onMouseLeave={() => onHighlight(null)}
        className="cursor-pointer rounded border px-2.5 py-2 text-center layer-bg layer-border"
      >
        <div className="text-[11px] font-semibold layer-text">Application data</div>
        <div className="mono text-[10.5px] faint">
          {innerPayload.length} bytes @ {innerPayload.offset}
        </div>
      </div>
    );
  }

  const box = boxes[index];
  const total = boxes.length;
  const stepNumber = mode === 'tx' ? total - index : index + 1;
  const active =
    highlight?.ranges.some((r) => r.offset === box.header.offset && r.length === box.header.length) ?? false;

  return (
    <div
      data-layer={box.layer}
      className="rounded-lg border transition-colors layer-border"
      style={{ background: active ? 'var(--layer-soft)' : 'transparent' }}
    >
      <div
        onMouseEnter={() =>
          onHighlight({
            ranges: [box.header],
            layer: box.layer,
            label: `${box.name} header`,
            detail: box.summary,
          })
        }
        onMouseLeave={() => onHighlight(null)}
        className="flex cursor-pointer items-center gap-2 rounded-t-lg px-2.5 py-1.5 layer-bg"
      >
        <span
          className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[9px] font-bold"
          style={{ background: 'var(--layer-color)', color: 'var(--bg)' }}
        >
          {stepNumber}
        </span>
        <span className="text-[11px] font-bold layer-text">{box.abbr}</span>
        <span className="truncate text-[10.5px] dim" title={box.summary}>
          {box.summary}
        </span>
        <span className="mono ml-auto shrink-0 text-[10px] faint">+{box.header.length} B</span>
      </div>

      <div className="px-2.5 py-2">
        <NestedBoxes
          boxes={boxes}
          index={index + 1}
          packet={packet}
          innerPayload={innerPayload}
          mode={mode}
          highlight={highlight}
          onHighlight={onHighlight}
        />
      </div>

      <div className="px-2.5 pb-1.5 text-[10px] faint">
        {box.pdu}
        {box.payload ? ` · carries ${box.payload.length} bytes` : ''}
      </div>
    </div>
  );
}
