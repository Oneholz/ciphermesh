/**
 * Pure Zero-Dependency QR Code Encoder (ISO/IEC 18004, Byte Mode, ECC Level L, Versions 1-20)
 * + Camera BarcodeDetector Scanner Helper
 */

// GF(256) lookup tables for Reed-Solomon (primitive polynomial 0x11d)
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    const factor = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], factor);
    }
    poly = next;
  }
  return poly;
}

function rsComputeEcc(data, ecCount) {
  const gen = rsGeneratorPoly(ecCount);
  const rem = new Uint8Array(ecCount);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0];
    for (let j = 0; j < ecCount - 1; j++) {
      rem[j] = rem[j + 1] ^ gfMul(gen[j + 1], factor);
    }
    rem[ecCount - 1] = gfMul(gen[ecCount], factor);
  }
  return rem;
}

// Level L version specs: [totalCodewords, ecPerBlock, numBlocksGroup1, dataPerBlockG1, numBlocksGroup2, dataPerBlockG2]
const VERSION_SPECS_L = [
  null,
  [26, 7, 1, 19, 0, 0],
  [44, 10, 1, 34, 0, 0],
  [70, 15, 1, 55, 0, 0],
  [100, 20, 1, 80, 0, 0],
  [134, 26, 1, 108, 0, 0],
  [172, 18, 2, 68, 0, 0],
  [196, 20, 2, 78, 0, 0],
  [242, 24, 2, 97, 0, 0],
  [292, 30, 2, 116, 0, 0],
  [346, 18, 2, 68, 2, 69],
  [404, 20, 4, 81, 0, 0],
  [466, 24, 2, 92, 2, 93],
  [532, 26, 4, 107, 0, 0],
  [581, 30, 3, 115, 1, 116],
  [655, 22, 5, 87, 1, 88],
  [733, 24, 5, 98, 1, 99],
  [815, 28, 1, 107, 5, 108],
  [901, 30, 5, 120, 1, 121],
  [991, 28, 3, 113, 4, 114],
  [1085, 28, 3, 107, 5, 108]
];

const ALIGNMENT_CENTERS = [
  [],
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
  [6, 26, 48, 70],
  [6, 26, 50, 74],
  [6, 30, 54, 78],
  [6, 30, 56, 82],
  [6, 30, 58, 86],
  [6, 34, 62, 90]
];

function chooseVersion(byteLen) {
  for (let v = 1; v < VERSION_SPECS_L.length; v++) {
    const [, , g1, d1, g2, d2] = VERSION_SPECS_L[v];
    const totalDataBytes = g1 * d1 + g2 * d2;
    const headerBits = 4 + (v <= 9 ? 8 : 16);
    const maxBytes = Math.floor((totalDataBytes * 8 - headerBits) / 8);
    if (byteLen <= maxBytes) return v;
  }
  throw new Error('QR_PAYLOAD_TOO_LARGE');
}

function encodeDataCodewords(bytes, version) {
  const [, , g1, d1, g2, d2] = VERSION_SPECS_L[version];
  const totalDataBytes = g1 * d1 + g2 * d2;
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) {
      bits.push((val >>> i) & 1);
    }
  };

  pushBits(0b0100, 4); // Byte mode
  pushBits(bytes.length, version <= 9 ? 8 : 16);
  for (let i = 0; i < bytes.length; i++) {
    pushBits(bytes[i], 8);
  }

  const maxBits = totalDataBytes * 8;
  const termLen = Math.min(4, maxBits - bits.length);
  pushBits(0, termLen);
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords = new Uint8Array(totalDataBytes);
  let idx = 0;
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    codewords[idx++] = b;
  }
  const padBytes = [0xec, 0x11];
  let padIdx = 0;
  while (idx < totalDataBytes) {
    codewords[idx++] = padBytes[padIdx];
    padIdx ^= 1;
  }
  return codewords;
}

function buildFinalCodewords(dataCodewords, version) {
  const [, ecPerBlock, g1, d1, g2, d2] = VERSION_SPECS_L[version];
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;

  for (let i = 0; i < g1; i++) {
    const block = dataCodewords.slice(offset, offset + d1);
    offset += d1;
    dataBlocks.push(block);
    ecBlocks.push(rsComputeEcc(block, ecPerBlock));
  }
  for (let i = 0; i < g2; i++) {
    const block = dataCodewords.slice(offset, offset + d2);
    offset += d2;
    dataBlocks.push(block);
    ecBlocks.push(rsComputeEcc(block, ecPerBlock));
  }

  const result = [];
  const maxDataLen = Math.max(d1, d2);
  for (let i = 0; i < maxDataLen; i++) {
    for (let b = 0; b < dataBlocks.length; b++) {
      if (i < dataBlocks[b].length) result.push(dataBlocks[b][i]);
    }
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (let b = 0; b < ecBlocks.length; b++) {
      result.push(ecBlocks[b][i]);
    }
  }
  return new Uint8Array(result);
}

function computeFormatBits(maskPattern) {
  // ECC Level L = 01
  const data = (0b01 << 3) | maskPattern;
  let rem = data << 10;
  for (let i = 14; i >= 10; i--) {
    if ((rem >>> i) & 1) rem ^= 0x537 << (i - 10);
  }
  return ((data << 10) | rem) ^ 0x5412;
}

function computeVersionBits(version) {
  let rem = version << 12;
  for (let i = 17; i >= 12; i--) {
    if ((rem >>> i) & 1) rem ^= 0x1f25 << (i - 12);
  }
  return (version << 12) | rem;
}

export function generateQrMatrix(text) {
  const bytes = new TextEncoder().encode(text);
  const version = chooseVersion(bytes.length);
  const size = version * 4 + 17;
  const matrix = Array.from({ length: size }, () => new Uint8Array(size));
  const isFunc = Array.from({ length: size }, () => new Uint8Array(size));

  const setModule = (r, c, val, fn = true) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    matrix[r][c] = val ? 1 : 0;
    if (fn) isFunc[r][c] = 1;
  };

  // Finder patterns + separators
  const drawFinder = (tr, tc) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = tr + dr;
        const c = tc + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const dist = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
        const dark = dist !== 2 && dist !== 4;
        setModule(r, c, dark, true);
      }
    }
  };
  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    setModule(6, i, i % 2 === 0, true);
    setModule(i, 6, i % 2 === 0, true);
  }

  // Alignment patterns
  const centers = ALIGNMENT_CENTERS[version];
  for (let i = 0; i < centers.length; i++) {
    for (let j = 0; j < centers.length; j++) {
      const cr = centers[i];
      const cc = centers[j];
      if (isFunc[cr][cc]) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const dist = Math.max(Math.abs(dr), Math.abs(dc));
          setModule(cr + dr, cc + dc, dist !== 1, true);
        }
      }
    }
  }

  // Reserve format info & dark module
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      setModule(8, i, 0, true);
      setModule(i, 8, 0, true);
    }
  }
  for (let i = size - 8; i < size; i++) {
    setModule(8, i, 0, true);
    setModule(i, 8, 0, true);
  }
  setModule(size - 8, 8, 1, true);

  // Version info for v >= 7
  if (version >= 7) {
    const vBits = computeVersionBits(version);
    for (let i = 0; i < 18; i++) {
      const bit = (vBits >>> i) & 1;
      const a = Math.floor(i / 3);
      const b = size - 11 + (i % 3);
      setModule(a, b, bit, true);
      setModule(b, a, bit, true);
    }
  }

  // Place data bits
  const dataCodewords = encodeDataCodewords(bytes, version);
  const allCodewords = buildFinalCodewords(dataCodewords, version);
  let bitIndex = 0;
  const totalBits = allCodewords.length * 8;

  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let vert = 0; vert < size; vert++) {
      const r = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        if (isFunc[r][c]) continue;
        let bit = 0;
        if (bitIndex < totalBits) {
          bit = (allCodewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1;
          bitIndex++;
        }
        matrix[r][c] = bit;
      }
    }
  }

  // Apply mask pattern 0 ((r + c) % 2 === 0) for fast deterministic encoding
  const maskPattern = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isFunc[r][c] && (r + c) % 2 === 0) {
        matrix[r][c] ^= 1;
      }
    }
  }

  // Write format info
  const fmt = computeFormatBits(maskPattern);
  const formatCoords1 = [
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
  ];
  for (let i = 0; i < 15; i++) {
    const bit = (fmt >>> i) & 1;
    const [r1, c1] = formatCoords1[i];
    matrix[r1][c1] = bit;
    if (i < 8) {
      matrix[size - 1 - i][8] = bit;
    } else {
      matrix[8][size - 15 + i] = bit;
    }
  }

  return matrix;
}

export function renderQrToCanvas(canvas, text, pixelSize = 240) {
  const matrix = generateQrMatrix(text);
  const quietZone = 4;
  const modules = matrix.length + quietZone * 2;
  const scale = Math.max(2, Math.floor(pixelSize / modules));
  const actualSize = modules * scale;

  canvas.width = actualSize;
  canvas.height = actualSize;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, actualSize, actualSize);
  ctx.fillStyle = '#000000';

  for (let r = 0; r < matrix.length; r++) {
    for (let c = 0; c < matrix.length; c++) {
      if (matrix[r][c]) {
        ctx.fillRect((c + quietZone) * scale, (r + quietZone) * scale, scale, scale);
      }
    }
  }
}

export function isCameraQrSupported() {
  return Boolean(
    navigator.mediaDevices &&
    navigator.mediaDevices.getUserMedia &&
    'BarcodeDetector' in window
  );
}

export async function startQrScanner(videoEl, onDetect) {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: 'environment' },
    audio: false
  });
  videoEl.srcObject = stream;
  await videoEl.play();

  const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
  let active = true;

  const tick = async () => {
    if (!active) return;
    try {
      if (videoEl.readyState >= 2) {
        const codes = await detector.detect(videoEl);
        if (codes.length > 0 && codes[0].rawValue) {
          active = false;
          stop();
          onDetect(codes[0].rawValue);
          return;
        }
      }
    } catch {
      // ignore transient frame read errors
    }
    if (active) requestAnimationFrame(tick);
  };

  const stop = () => {
    active = false;
    stream.getTracks().forEach((track) => track.stop());
    videoEl.srcObject = null;
  };

  requestAnimationFrame(tick);
  return stop;
}
