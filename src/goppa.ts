interface ToyFieldConfig {
  m: number;
  primitivePolynomial: number;
}

const GF16: ToyFieldConfig = {
  m: 4,
  primitivePolynomial: 0b10011
};

function gfAdd(a: number, b: number): number {
  return a ^ b;
}

function gfMul(a: number, b: number, cfg: ToyFieldConfig): number {
  let result = 0;
  let aa = a;
  let bb = b;

  while (bb > 0) {
    if (bb & 1) {
      result ^= aa;
    }
    bb >>= 1;
    aa <<= 1;
    if (aa & (1 << cfg.m)) {
      aa ^= cfg.primitivePolynomial;
    }
  }

  return result & ((1 << cfg.m) - 1);
}

function gfPow(a: number, exponent: number, cfg: ToyFieldConfig): number {
  let out = 1;
  for (let i = 0; i < exponent; i += 1) {
    out = gfMul(out, a, cfg);
  }
  return out;
}

function gfInv(a: number, cfg: ToyFieldConfig): number {
  if (a === 0) {
    throw new Error("No inverse for zero in GF(2^m)");
  }
  return gfPow(a, (1 << cfg.m) - 2, cfg);
}

function evalPoly(coeffs: number[], x: number, cfg: ToyFieldConfig): number {
  return coeffs.reduce((acc, coeff) => gfAdd(gfMul(acc, x, cfg), coeff), 0);
}

export interface GoppaVisual {
  supportSet: number[];
  goppaPolynomial: number[];
  syndromeVector: number[];
  generatorMatrix: string[];
  scrambleMatrix: string[];
  permutationMatrix: string[];
}

export function buildToyGoppaVisual(): GoppaVisual {
  const supportSet = [1, 2, 4, 8, 3, 6, 12, 11];
  const goppaPolynomial = [1, 0, 1, 1];
  const toyErrorPositions = [1, 4, 6];

  const syndromeVector = supportSet.map((alpha, idx) => {
    if (!toyErrorPositions.includes(idx)) {
      return 0;
    }

    const denominator = evalPoly(goppaPolynomial, alpha, GF16);
    const safeDenominator = denominator === 0 ? 1 : denominator;
    return gfInv(safeDenominator, GF16);
  });

  return {
    supportSet,
    goppaPolynomial,
    syndromeVector,
    generatorMatrix: [
      "1 0 0 1 1 0 1 0",
      "0 1 0 1 0 1 0 1",
      "0 0 1 0 1 1 1 0"
    ],
    scrambleMatrix: [
      "1 1 0",
      "0 1 1",
      "1 0 1"
    ],
    permutationMatrix: [
      "0 0 1 0 0 0 0 0",
      "1 0 0 0 0 0 0 0",
      "0 0 0 1 0 0 0 0",
      "0 1 0 0 0 0 0 0",
      "0 0 0 0 0 1 0 0",
      "0 0 0 0 1 0 0 0",
      "0 0 0 0 0 0 0 1",
      "0 0 0 0 0 0 1 0"
    ]
  };
}
