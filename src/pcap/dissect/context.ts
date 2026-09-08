/**
 * Shared state threaded through the dissectors, plus the small builder helpers
 * that keep the individual protocol modules terse.
 */

import type { Field, OsiLayer, ProtocolLayer } from '../types';
import { what } from '../../data/glossary';

export class DissectContext {
  readonly bytes: Uint8Array;
  readonly protocols: ProtocolLayer[] = [];
  readonly warnings: string[] = [];

  /** Highest-layer protocol abbreviation seen so far. */
  protocol = 'Unknown';
  /** Wireshark-style one-line description; each dissector may refine it. */
  info = '';
  source = '';
  destination = '';

  /** Everything the quick filter should be able to match on. */
  readonly searchTerms = new Set<string>();

  /** Raw IP address bytes, kept for TCP/UDP pseudo-header checksums. */
  ipSrcBytes?: Uint8Array;
  ipDstBytes?: Uint8Array;
  ipVersion?: 4 | 6;
  ipProtocol?: number;

  /**
   * Absolute end offset of the network-layer payload.
   *
   * This is what stops Ethernet padding from being mistaken for transport
   * payload: a 54-byte TCP ACK arrives inside a 60-byte frame, and only the IP
   * Total Length field knows where the real data stops.
   */
  transportEnd?: number;

  /** Set once a TCP/UDP port pair is known, used for payload heuristics. */
  srcPort?: number;
  dstPort?: number;

  /** Guards against malformed packets producing unbounded dissector recursion. */
  depth = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  add(layer: ProtocolLayer): ProtocolLayer {
    this.protocols.push(layer);
    if (!layer.virtual && !layer.trailer) this.protocol = layer.abbr;
    return layer;
  }

  term(...values: (string | number | undefined)[]): void {
    for (const v of values) {
      if (v === undefined || v === null || v === '') continue;
      this.searchTerms.add(String(v).toLowerCase());
    }
  }

  warn(message: string): void {
    if (!this.warnings.includes(message)) this.warnings.push(message);
  }

  /** True when `count` bytes starting at `offset` are actually present. */
  has(offset: number, count: number): boolean {
    return offset >= 0 && offset + count <= this.bytes.length;
  }

  /** Report a truncated header and stop dissecting further down the stack. */
  truncated(protocolName: string, offset: number, needed: number): void {
    this.warn(
      `${protocolName} header is truncated: ${needed} bytes needed at offset ${offset}, ` +
        `only ${Math.max(0, this.bytes.length - offset)} captured.`,
    );
  }
}

let fieldCounter = 0;

export function resetFieldIds(): void {
  fieldCounter = 0;
}

export interface FieldSpec {
  name: string;
  value: string;
  offset: number;
  length: number;
  layer: OsiLayer;
  /** Glossary key for the static "what does this do" text. */
  key?: string;
  /** Literal static text, when no glossary entry applies. */
  whatText?: string;
  /** Contextual "why does this value matter" note. */
  why?: string;
  bits?: { offset: number; length: number };
  children?: Field[];
  synthetic?: boolean;
  note?: 'info' | 'warn' | 'error';
}

export function field(spec: FieldSpec): Field {
  return {
    id: `f${fieldCounter++}`,
    name: spec.name,
    value: spec.value,
    offset: spec.offset,
    length: spec.length,
    layer: spec.layer,
    what: spec.key ? what(spec.key, spec.whatText ?? '') : (spec.whatText ?? ''),
    why: spec.why,
    bits: spec.bits,
    children: spec.children,
    synthetic: spec.synthetic,
    note: spec.note,
  };
}
