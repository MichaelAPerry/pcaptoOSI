import { useEffect, useRef, useState } from 'react';
import type { DissectedPacket, Field, OsiLayer } from '../pcap/types';
import type { LayerView } from '../pcap/osi';
import type { Highlight } from '../lib/highlight';

interface Props {
  packet: DissectedPacket;
  layers: LayerView[];
  highlight: Highlight | null;
  onHighlight: (h: Highlight | null) => void;
  selectedField: Field | null;
  onSelectField: (field: Field | null) => void;
  teacherMode: boolean;
}

/**
 * The OSI layer inspector.
 *
 * Layers are always all seven, always in order, and a layer with nothing in it
 * says so and explains why — that absence is one of the most important things
 * a student can learn from a real capture.
 */
export function OsiInspector({ packet, layers, highlight, onHighlight, selectedField, onSelectField, teacherMode }: Props) {
  const [collapsed, setCollapsed] = useState<Set<OsiLayer>>(new Set());

  // Reset collapse state when the selected packet changes.
  useEffect(() => setCollapsed(new Set()), [packet.index]);

  function toggle(layer: OsiLayer): void {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(layer)) next.delete(layer);
      else next.add(layer);
      return next;
    });
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center justify-between border-b px-3 py-2 hairline">
        <h2 className="text-[12px] font-semibold tracking-wide uppercase dim">OSI layer dissection</h2>
        <span className="text-[11px] faint">frame {packet.index}</span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {[...layers].reverse().map((view) => {
          const isCollapsed = collapsed.has(view.layer);
          const byteCount = view.ranges.reduce((n, r) => n + r.length, 0);
          const highlighted = highlight?.layer === view.layer;

          return (
            <section key={view.layer} data-layer={view.layer} className="border-b hairline">
              <button
                onClick={() => toggle(view.layer)}
                onMouseEnter={() =>
                  view.ranges.length > 0 &&
                  onHighlight({
                    ranges: view.ranges,
                    layer: view.layer,
                    label: `Layer ${view.layer} — ${view.name}`,
                    detail: view.label,
                  })
                }
                onMouseLeave={() => onHighlight(null)}
                className={`flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors focus-ring ${
                  highlighted ? 'layer-bg' : 'hover:bg-[var(--bg-hover)]'
                } ${view.present ? '' : 'opacity-55'}`}
              >
                <span
                  className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-[11px] font-bold"
                  style={{ background: 'var(--layer-soft)', color: 'var(--layer-color)' }}
                >
                  {view.layer}
                </span>
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="flex items-baseline gap-2">
                    <span className="text-[13px] font-semibold layer-text">{view.name}</span>
                    <span className="text-[10px] tracking-wide uppercase faint">{view.pdu}</span>
                  </span>
                  <span className="truncate text-[11.5px] dim">{view.label}</span>
                </span>
                {byteCount > 0 && (
                  <span className="mono shrink-0 text-[11px] faint">{byteCount} B</span>
                )}
                <span className={`shrink-0 faint transition-transform ${isCollapsed ? '' : 'rotate-90'}`}>›</span>
              </button>

              {!isCollapsed && (
                <div className="pb-1.5">
                  {!view.present && view.absenceNote && (
                    <p className="mx-3 mb-2 rounded border-l-2 px-2.5 py-1.5 text-[11.5px] leading-relaxed layer-bg layer-border dim">
                      {view.absenceNote}
                    </p>
                  )}

                  {view.protocols.map((proto) => (
                    <div key={`${proto.id}-${proto.layer}`} className="mb-1">
                      <div
                        className="flex items-baseline gap-2 px-3 py-1"
                        onMouseEnter={() =>
                          proto.length > 0 &&
                          onHighlight({
                            ranges: [{ offset: proto.offset, length: proto.length }],
                            layer: view.layer,
                            label: proto.name,
                            detail: proto.summary,
                          })
                        }
                        onMouseLeave={() => onHighlight(null)}
                      >
                        <span className="text-[11px] font-semibold tracking-wide uppercase layer-text">{proto.abbr}</span>
                        <span className="truncate text-[11.5px] dim" title={proto.summary}>
                          {proto.summary}
                        </span>
                      </div>
                    </div>
                  ))}

                  {view.fields.map((f) => (
                    <FieldRow
                      key={f.id}
                      field={f}
                      depth={0}
                      highlight={highlight}
                      onHighlight={onHighlight}
                      selectedField={selectedField}
                      onSelectField={onSelectField}
                      teacherMode={teacherMode}
                    />
                  ))}
                </div>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}

interface RowProps {
  field: Field;
  depth: number;
  highlight: Highlight | null;
  onHighlight: (h: Highlight | null) => void;
  selectedField: Field | null;
  onSelectField: (field: Field | null) => void;
  teacherMode: boolean;
}

function FieldRow({ field, depth, highlight, onHighlight, selectedField, onSelectField, teacherMode }: RowProps) {
  const [open, setOpen] = useState(depth < 1 && (field.children?.length ?? 0) <= 4);
  const ref = useRef<HTMLDivElement>(null);
  const hasChildren = (field.children?.length ?? 0) > 0;
  const isHighlighted = highlight?.fieldId === field.id;
  const isSelected = selectedField?.id === field.id;

  // When the hex pane points at this field, bring it into view.
  useEffect(() => {
    if (isHighlighted && ref.current) {
      ref.current.scrollIntoView({ block: 'nearest' });
    }
  }, [isHighlighted]);

  const noteColor =
    field.note === 'error' ? '#f2724f' : field.note === 'warn' ? '#f0a848' : undefined;

  return (
    <div ref={ref}>
      <div
        data-layer={field.layer}
        onMouseEnter={() =>
          onHighlight({
            ranges: field.length > 0 ? [{ offset: field.offset, length: field.length }] : [],
            fieldId: field.id,
            layer: field.layer,
            label: field.name,
            detail: field.value,
          })
        }
        onMouseLeave={() => onHighlight(null)}
        onClick={() => onSelectField(isSelected ? null : field)}
        style={{ paddingLeft: 12 + depth * 14 }}
        className={`flex cursor-pointer items-baseline gap-2 py-[3px] pr-3 transition-colors ${
          isHighlighted || isSelected ? 'layer-bg' : 'hover:bg-[var(--bg-hover)]'
        }`}
      >
        <button
          onClick={(e) => {
            e.stopPropagation();
            setOpen((v) => !v);
          }}
          className={`w-3 shrink-0 text-[10px] faint transition-transform ${hasChildren ? '' : 'invisible'} ${open ? 'rotate-90' : ''}`}
          aria-label={open ? 'Collapse' : 'Expand'}
        >
          ›
        </button>
        <span className="w-[46%] min-w-0 shrink-0 truncate text-[12px]" title={field.name}>
          {field.name}
          {field.synthetic && <span className="ml-1 text-[10px] faint">(derived)</span>}
        </span>
        <span
          className="mono min-w-0 flex-1 truncate text-[11.5px]"
          style={{ color: noteColor ?? 'var(--text-dim)' }}
          title={field.value}
        >
          {field.value}
        </span>
        {field.length > 0 && <span className="mono shrink-0 text-[10px] faint">@{field.offset}</span>}
      </div>

      {/* Pinned fields get the side drawer instead, so the text is never shown twice. */}
      {teacherMode && (field.what || field.why) && isHighlighted && !isSelected && (
        <div
          data-layer={field.layer}
          className="animate-in mx-3 mb-1.5 rounded border-l-2 px-2.5 py-2 text-[11.5px] leading-relaxed layer-bg layer-border"
          style={{ marginLeft: 12 + depth * 14 }}
        >
          {field.what && (
            <p className="dim">
              <span className="font-semibold layer-text">What it does. </span>
              {field.what}
            </p>
          )}
          {field.why && (
            <p className="mt-1.5 dim">
              <span className="font-semibold layer-text">Why this value matters. </span>
              {field.why}
            </p>
          )}
        </div>
      )}

      {open &&
        field.children?.map((c) => (
          <FieldRow
            key={c.id}
            field={c}
            depth={depth + 1}
            highlight={highlight}
            onHighlight={onHighlight}
            selectedField={selectedField}
            onSelectField={onSelectField}
            teacherMode={teacherMode}
          />
        ))}
    </div>
  );
}
