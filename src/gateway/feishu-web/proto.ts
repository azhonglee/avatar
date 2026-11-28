/**
 * Schema-free bounded Protobuf wire codec for Feishu personal Web gateway & Frontier frames.
 * Rejects oversized payloads, invalid field numbers, deprecated group wire types, and truncated inputs.
 */

export const MAX_WIRE_BYTES = 8 * 1024 * 1024; // 8 MiB

export const WIRE_VARINT = 0;
export const WIRE_FIXED64 = 1;
export const WIRE_BYTES = 2;
export const WIRE_FIXED32 = 5;

export type WireType = typeof WIRE_VARINT | typeof WIRE_FIXED64 | typeof WIRE_BYTES | typeof WIRE_FIXED32;

export interface ProtoValue {
  type: WireType;
  bytes?: Buffer;
  uint?: bigint;
}

export class ProtoWireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtoWireError";
  }
}

/** Standard protobuf field map preserving wire order and last-scalar-wins semantics. */
export class ProtoFields {
  private readonly map: Map<number, ProtoValue[]>;

  constructor(map: Map<number, ProtoValue[]> = new Map()) {
    this.map = map;
  }

  has(field: number): boolean {
    return (this.map.get(field)?.length ?? 0) > 0;
  }

  lastField(field: number): ProtoValue | undefined {
    const vals = this.map.get(field);
    return vals?.length ? vals[vals.length - 1] : undefined;
  }

  allFields(field: number): readonly ProtoValue[] {
    return this.map.get(field) ?? [];
  }

  bytes(field: number): Buffer {
    const vals = this.map.get(field);
    if (!vals?.length) return Buffer.alloc(0);
    const last = vals[vals.length - 1];
    return last.type === WIRE_BYTES && last.bytes ? last.bytes : Buffer.alloc(0);
  }

  str(field: number): string {
    const buf = this.bytes(field);
    return buf.length ? buf.toString("utf8") : "";
  }

  uint64(field: number): bigint {
    const vals = this.map.get(field);
    if (!vals?.length) return 0n;
    const last = vals[vals.length - 1];
    return last.uint ?? 0n;
  }

  uint(field: number): number {
    return Number(this.uint64(field));
  }

  int32(field: number): number {
    return Number(BigInt.asIntN(32, this.uint64(field)));
  }

  allBytes(field: number): Buffer[] {
    const vals = this.map.get(field);
    if (!vals?.length) return [];
    const out: Buffer[] = [];
    for (const v of vals) {
      if (v.type === WIRE_BYTES && v.bytes) out.push(v.bytes);
    }
    return out;
  }

  allUints(field: number): bigint[] {
    const vals = this.map.get(field);
    if (!vals?.length) return [];
    const out: bigint[] = [];
    for (const v of vals) {
      if (v.type !== WIRE_BYTES && v.uint !== undefined) out.push(v.uint);
    }
    return out;
  }
}

function readVarint(buf: Uint8Array, offset: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  while (pos < buf.length) {
    const b = buf[pos++];
    // 第 10 字节位于 bit 63，仅允许 0x00 或 0x01（且不得再有续接位 0x80），否则超出 uint64 范围
    if (shift >= 64n || (shift === 63n && b > 1)) {
      throw new ProtoWireError("protobuf varint overflow");
    }
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [result, pos];
    shift += 7n;
  }
  throw new ProtoWireError("truncated protobuf varint");
}

/** Parse raw protobuf wire bytes within a strict byte ceiling. */
export function parseProto(input: Uint8Array, limit = MAX_WIRE_BYTES): ProtoFields {
  if (limit <= 0 || input.byteLength > limit) {
    throw new ProtoWireError("protobuf wire limit exceeded");
  }
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const map = new Map<number, ProtoValue[]>();
  let pos = 0;
  while (pos < buf.length) {
    const [tag, afterTag] = readVarint(buf, pos);
    pos = afterTag;
    const wireType = Number(tag & 7n);
    const fieldBig = tag >> 3n;
    if (fieldBig <= 0n || fieldBig > 0x1fffffffn) {
      throw new ProtoWireError("invalid protobuf field number");
    }
    const field = Number(fieldBig);
    let val: ProtoValue;
    if (wireType === WIRE_VARINT) {
      const [u, next] = readVarint(buf, pos);
      pos = next;
      val = { type: WIRE_VARINT, uint: u };
    } else if (wireType === WIRE_BYTES) {
      const [lenBig, afterLen] = readVarint(buf, pos);
      const len = Number(lenBig);
      if (!Number.isSafeInteger(len) || len < 0 || afterLen + len > buf.length) {
        throw new ProtoWireError("truncated protobuf length-delimited field");
      }
      pos = afterLen + len;
      val = { type: WIRE_BYTES, bytes: buf.subarray(afterLen, pos) };
    } else if (wireType === WIRE_FIXED32) {
      if (pos + 4 > buf.length) throw new ProtoWireError("truncated protobuf fixed32");
      val = { type: WIRE_FIXED32, uint: BigInt(buf.readUInt32LE(pos)) };
      pos += 4;
    } else if (wireType === WIRE_FIXED64) {
      if (pos + 8 > buf.length) throw new ProtoWireError("truncated protobuf fixed64");
      val = { type: WIRE_FIXED64, uint: buf.readBigUInt64LE(pos) };
      pos += 8;
    } else {
      throw new ProtoWireError(`unsupported protobuf wire type: ${wireType}`);
    }
    const arr = map.get(field);
    if (arr) arr.push(val);
    else map.set(field, [val]);
  }
  return new ProtoFields(map);
}

function encodeVarint(value: number | bigint): Buffer {
  let v = typeof value === "bigint" ? BigInt.asUintN(64, value) : BigInt.asUintN(64, BigInt(Math.trunc(value)));
  const out: number[] = [];
  while (v >= 0x80n) {
    out.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  out.push(Number(v));
  return Buffer.from(out);
}

function encodeTag(field: number, wireType: WireType): Buffer {
  if (!Number.isInteger(field) || field <= 0) throw new ProtoWireError(`invalid field number: ${field}`);
  return encodeVarint((BigInt(field) << 3n) | BigInt(wireType));
}

/** Builder for deterministic schema-free protobuf payloads. */
export class ProtoWriter {
  private readonly chunks: Buffer[] = [];

  uint(field: number, value: number | bigint): this {
    this.chunks.push(encodeTag(field, WIRE_VARINT), encodeVarint(value));
    return this;
  }

  bytes(field: number, value: Uint8Array): this {
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    this.chunks.push(encodeTag(field, WIRE_BYTES), encodeVarint(buf.length), buf);
    return this;
  }

  str(field: number, value: string): this {
    return this.bytes(field, Buffer.from(value, "utf8"));
  }

  finish(): Buffer {
    return Buffer.concat(this.chunks);
  }
}
