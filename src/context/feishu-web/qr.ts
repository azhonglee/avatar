/**
 * Minimal zero-dependency QR Code generator (ISO/IEC 18004, Byte mode, ECC Level M, Versions 1..10).
 * Used by `pa context web-login` to render scannable QR codes in UTF-8 terminals and optional SVG files.
 */

interface VersionSpec {
  version: number;
  size: number;
  totalCodewords: number;
  eccPerBlock: number;
  blocks: [number, number][]; // [count, dataCodewords]
  alignments: number[];
}

// ISO/IEC 18004 ECC Level M parameters for Versions 1..10 (covers up to 213 UTF-8 bytes).
const VERSIONS: VersionSpec[] = [
  { version: 1, size: 21, totalCodewords: 26, eccPerBlock: 10, blocks: [[1, 16]], alignments: [] },
  { version: 2, size: 25, totalCodewords: 44, eccPerBlock: 16, blocks: [[1, 28]], alignments: [6, 18] },
  { version: 3, size: 29, totalCodewords: 70, eccPerBlock: 26, blocks: [[1, 44]], alignments: [6, 22] },
  { version: 4, size: 33, totalCodewords: 100, eccPerBlock: 18, blocks: [[2, 32]], alignments: [6, 26] },
  { version: 5, size: 37, totalCodewords: 134, eccPerBlock: 24, blocks: [[2, 43]], alignments: [6, 30] },
  { version: 6, size: 41, totalCodewords: 172, eccPerBlock: 16, blocks: [[4, 27]], alignments: [6, 34] },
  { version: 7, size: 45, totalCodewords: 196, eccPerBlock: 18, blocks: [[4, 31]], alignments: [6, 22, 38] },
  { version: 8, size: 49, totalCodewords: 242, eccPerBlock: 22, blocks: [[2, 38], [2, 39]], alignments: [6, 24, 42] },
  { version: 9, size: 53, totalCodewords: 292, eccPerBlock: 22, blocks: [[3, 36], [2, 37]], alignments: [6, 26, 46] },
  { version: 10, size: 57, totalCodewords: 346, eccPerBlock: 26, blocks: [[4, 43], [1, 44]], alignments: [6, 28, 50] },
];

// GF(256) with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGenerator(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    const root = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], root);
    }
    poly = next;
  }
  return poly;
}

function rsRemainder(data: Uint8Array, eccLen: number): Uint8Array {
  const gen = rsGenerator(eccLen);
  const rem = new Uint8Array(eccLen);
  for (const byte of data) {
    const factor = byte ^ rem[0];
    rem.copyWithin(0, 1);
    rem[eccLen - 1] = 0;
    for (let j = 0; j < eccLen; j++) {
      rem[j] ^= gfMul(gen[j + 1], factor);
    }
  }
  return rem;
}

function dataCapacity(spec: VersionSpec): number {
  return spec.blocks.reduce((sum, [count, cw]) => sum + count * cw, 0);
}

function pickVersion(byteLen: number): VersionSpec {
  for (const spec of VERSIONS) {
    const countBits = spec.version <= 9 ? 8 : 16;
    const neededBits = 4 + countBits + byteLen * 8;
    if (Math.ceil(neededBits / 8) <= dataCapacity(spec)) return spec;
  }
  throw new Error(`QR 内容过长 (${byteLen} bytes)`);
}

function encodeCodewords(bytes: Uint8Array, spec: VersionSpec): Uint8Array {
  const cap = dataCapacity(spec);
  const bits: number[] = [];
  const pushBits = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };
  pushBits(0b0100, 4); // Byte mode
  pushBits(bytes.length, spec.version <= 9 ? 8 : 16);
  for (const b of bytes) pushBits(b, 8);
  const maxBits = cap * 8;
  pushBits(0, Math.min(4, maxBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const data = new Uint8Array(cap);
  for (let i = 0; i < bits.length / 8; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
    data[i] = b;
  }
  let padIdx = 0;
  for (let i = bits.length / 8; i < cap; i++) {
    data[i] = padIdx++ % 2 === 0 ? 0xec : 0x11;
  }

  // Split into RS blocks and interleave
  const dataBlocks: Uint8Array[] = [];
  const eccBlocks: Uint8Array[] = [];
  let offset = 0;
  for (const [count, cw] of spec.blocks) {
    for (let i = 0; i < count; i++) {
      const blk = data.subarray(offset, offset + cw);
      offset += cw;
      dataBlocks.push(blk);
      eccBlocks.push(rsRemainder(blk, spec.eccPerBlock));
    }
  }
  const out = new Uint8Array(spec.totalCodewords);
  let pos = 0;
  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxDataLen; i++) {
    for (const blk of dataBlocks) if (i < blk.length) out[pos++] = blk[i];
  }
  for (let i = 0; i < spec.eccPerBlock; i++) {
    for (const blk of eccBlocks) out[pos++] = blk[i];
  }
  return out;
}

function formatBits(mask: number): number {
  // ECC Level M = 00
  const data = (0b00 << 3) | (mask & 0x7);
  let rem = data << 10;
  for (let i = 4; i >= 0; i--) {
    if (rem & (1 << (i + 10))) rem ^= 0x537 << i;
  }
  return ((data << 10) | rem) ^ 0x5412;
}

function versionBits(version: number): number {
  let rem = version << 12;
  for (let i = 5; i >= 0; i--) {
    if (rem & (1 << (i + 12))) rem ^= 0x1f25 << i;
  }
  return (version << 12) | rem;
}

function maskBit(mask: number, r: number, c: number): boolean {
  switch (mask) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
    default: return false;
  }
}

function penaltyScore(grid: Uint8Array, size: number): number {
  let score = 0;
  const at = (r: number, c: number) => grid[r * size + c];
  // Rule 1: runs of 5+ same color in rows and cols
  for (let r = 0; r < size; r++) {
    let runColor = at(r, 0);
    let runLen = 1;
    for (let c = 1; c < size; c++) {
      if (at(r, c) === runColor) {
        runLen++;
        if (runLen === 5) score += 3;
        else if (runLen > 5) score += 1;
      } else {
        runColor = at(r, c);
        runLen = 1;
      }
    }
  }
  for (let c = 0; c < size; c++) {
    let runColor = at(0, c);
    let runLen = 1;
    for (let r = 1; r < size; r++) {
      if (at(r, c) === runColor) {
        runLen++;
        if (runLen === 5) score += 3;
        else if (runLen > 5) score += 1;
      } else {
        runColor = at(r, c);
        runLen = 1;
      }
    }
  }
  // Rule 2: 2x2 blocks
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = at(r, c);
      if (v === at(r, c + 1) && v === at(r + 1, c) && v === at(r + 1, c + 1)) score += 3;
    }
  }
  // Rule 4: dark ratio balance
  let dark = 0;
  for (const v of grid) if (v) dark++;
  const pct = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(pct - 50) / 5) * 10;
  return score;
}

export interface QrMatrix {
  size: number;
  modules: Uint8Array; // 1 = dark, 0 = light, row-major
}

/** Generate a QR matrix (ECC-M, Byte mode) for the given UTF-8 text. */
export function encodeQrMatrix(text: string): QrMatrix {
  const bytes = Buffer.from(text, "utf8");
  const spec = pickVersion(bytes.length);
  const size = spec.size;
  const codewords = encodeCodewords(bytes, spec);

  const base = new Uint8Array(size * size);
  const func = new Uint8Array(size * size);
  const setFunc = (r: number, c: number, dark: boolean) => {
    if (r < 0 || c < 0 || r >= size || c >= size) return;
    base[r * size + c] = dark ? 1 : 0;
    func[r * size + c] = 1;
  };

  // Finder patterns + separators
  const drawFinder = (tr: number, tc: number) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = tr + dr;
        const c = tc + dc;
        if (r < 0 || c < 0 || r >= size || c >= size) continue;
        const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        const border = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const inner = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        setFunc(r, c, inOuter && (border || inner));
      }
    }
  };
  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Alignment patterns
  for (const ar of spec.alignments) {
    for (const ac of spec.alignments) {
      if (func[ar * size + ac]) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const dist = Math.max(Math.abs(dr), Math.abs(dc));
          setFunc(ar + dr, ac + dc, dist !== 1);
        }
      }
    }
  }

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    if (!func[6 * size + i]) setFunc(6, i, i % 2 === 0);
    if (!func[i * size + 6]) setFunc(i, 6, i % 2 === 0);
  }

  // Reserve format info + dark module
  setFunc(size - 8, 8, true);
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      if (!func[8 * size + i]) setFunc(8, i, false);
      if (!func[i * size + 8]) setFunc(i, 8, false);
    }
  }
  for (let i = 0; i < 8; i++) {
    if (!func[8 * size + (size - 1 - i)]) setFunc(8, size - 1 - i, false);
    if (i < 7 && !func[(size - 1 - i) * size + 8]) setFunc(size - 1 - i, 8, false);
  }

  // Version info for >= 7
  if (spec.version >= 7) {
    const vb = versionBits(spec.version);
    for (let i = 0; i < 18; i++) {
      const bit = ((vb >> i) & 1) !== 0;
      const a = Math.floor(i / 3);
      const b = size - 11 + (i % 3);
      setFunc(a, b, bit);
      setFunc(b, a, bit);
    }
  }

  // Place data bits in upward/downward zigzag columns
  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      const r = upward ? size - 1 - step : step;
      for (let dx = 0; dx < 2; dx++) {
        const c = right - dx;
        if (func[r * size + c]) continue;
        let bit = 0;
        if (bitIdx < totalBits) {
          bit = (codewords[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1;
          bitIdx++;
        }
        base[r * size + c] = bit;
      }
    }
    upward = !upward;
  }

  const applyFormat = (grid: Uint8Array, mask: number) => {
    const fb = formatBits(mask);
    for (let i = 0; i <= 5; i++) grid[8 * size + i] = (fb >> (14 - i)) & 1;
    grid[8 * size + 7] = (fb >> 8) & 1;
    grid[8 * size + 8] = (fb >> 7) & 1;
    grid[7 * size + 8] = (fb >> 6) & 1;
    for (let i = 9; i < 15; i++) grid[(14 - i) * size + 8] = (fb >> (14 - i)) & 1;
    for (let i = 0; i < 8; i++) grid[8 * size + (size - 1 - i)] = (fb >> i) & 1;
    for (let i = 0; i < 7; i++) grid[(size - 1 - i) * size + 8] = (fb >> (14 - i)) & 1;
  };

  let bestGrid = base;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const candidate = new Uint8Array(base);
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (!func[r * size + c] && maskBit(mask, r, c)) {
          candidate[r * size + c] ^= 1;
        }
      }
    }
    applyFormat(candidate, mask);
    const s = penaltyScore(candidate, size);
    if (s < bestScore) {
      bestScore = s;
      bestGrid = candidate;
    }
  }

  return { size, modules: bestGrid };
}

/** Render QR matrix for dark or light UTF-8 terminals using compact half-block characters with quiet zone. */
export function renderQrTerminal(text: string, quiet = 2): string {
  const { size, modules } = encodeQrMatrix(text);
  const full = size + quiet * 2;
  const darkAt = (r: number, c: number) => {
    const mr = r - quiet;
    const mc = c - quiet;
    if (mr < 0 || mc < 0 || mr >= size || mc >= size) return false;
    return modules[mr * size + mc] === 1;
  };
  const lines: string[] = [];
  // Invert visually onto white quiet-zone background: white cell = █ (light), dark cell = space
  // Using standard white-on-black terminal convention (most terminals are dark bg):
  // light module -> full block (white), dark module -> space (black) yields crisp white quiet zone!
  for (let r = 0; r < full; r += 2) {
    let line = "";
    for (let c = 0; c < full; c++) {
      const topLight = !darkAt(r, c);
      const botLight = r + 1 < full ? !darkAt(r + 1, c) : true;
      if (topLight && botLight) line += "█";
      else if (topLight) line += "▀";
      else if (botLight) line += "▄";
      else line += " ";
    }
    lines.push(line);
  }
  return lines.join("\n");
}

/** Render crisp standalone SVG QR code (can be saved to disk and opened in any browser). */
export function renderQrSvg(text: string, cellSize = 8, quiet = 4): string {
  const { size, modules } = encodeQrMatrix(text);
  const dim = (size + quiet * 2) * cellSize;
  const rects: string[] = [];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r * size + c] === 1) {
        rects.push(`<rect x="${(c + quiet) * cellSize}" y="${(r + quiet) * cellSize}" width="${cellSize}" height="${cellSize}"/>`);
      }
    }
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${dim}" height="${dim}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#ffffff"/><g fill="#000000">${rects.join("")}</g></svg>\n`;
}
