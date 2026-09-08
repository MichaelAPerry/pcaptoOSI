import type { ByteRange } from '../pcap/osi';
import type { OsiLayer } from '../pcap/types';

/**
 * What the mouse is currently pointing at, shared by every pane.
 *
 * This one object is what makes the tool feel connected: hovering a field in
 * the inspector, a box in the encapsulation diagram, or a byte in the hex pane
 * all produce the same shape, and every pane reacts to it.
 */
export interface Highlight {
  ranges: ByteRange[];
  fieldId?: string;
  layer?: OsiLayer;
  label: string;
  detail?: string;
}

export function rangesContain(ranges: ByteRange[], offset: number): boolean {
  return ranges.some((r) => offset >= r.offset && offset < r.offset + r.length);
}
