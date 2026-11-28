import QRCode from "qrcode";

/**
 * QR code renderer backed by the `qrcode` library (ISO/IEC 18004, Versions 1..40, ECC Level M).
 * Used by `pa context web-login` to render scannable QR codes in UTF-8 terminals and optional SVG files.
 */

export interface QrMatrix {
  size: number;
  modules: Uint8Array; // 1 = dark, 0 = light, row-major
}

/** Generate a QR matrix (ECC-M) for the given UTF-8 text. */
export function encodeQrMatrix(text: string): QrMatrix {
  const qr = QRCode.create(text, { errorCorrectionLevel: "M" });
  const size = qr.modules.size;
  const modules = new Uint8Array(size * size);
  for (let i = 0; i < modules.length; i++) {
    modules[i] = qr.modules.data[i] ? 1 : 0;
  }
  return { size, modules };
}

/** Render QR matrix with explicit black-on-white ANSI colors and a 4-module white quiet zone (theme-independent for dark and light terminals). */
export function renderQrTerminal(text: string, quiet = 4): string {
  const { size, modules } = encodeQrMatrix(text);
  const full = size + quiet * 2;
  const darkAt = (r: number, c: number): boolean => {
    const mr = r - quiet;
    const mc = c - quiet;
    if (mr < 0 || mc < 0 || mr >= size || mc >= size) return false;
    return modules[mr * size + mc] === 1;
  };
  const lines: string[] = [];
  const BLACK_ON_WHITE = "\x1b[30;47m";
  const RESET = "\x1b[0m";
  for (let r = 0; r < full; r += 2) {
    let line = BLACK_ON_WHITE;
    for (let c = 0; c < full; c++) {
      const topDark = darkAt(r, c);
      const botDark = r + 1 < full ? darkAt(r + 1, c) : false;
      if (topDark && botDark) line += "█";
      else if (topDark) line += "▀";
      else if (botDark) line += "▄";
      else line += " ";
    }
    lines.push(line + RESET);
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
