import { SignJWT, importJWK, generateKeyPair, exportJWK } from 'jose';
import { randomBytes } from 'crypto';
// Simple base58 decoder for DID keys (base58btc alphabet)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Simple base58btc decoder for DID keys
 */
function decodeBase58btc(encoded: string): Uint8Array {
  const alphabet = BASE58_ALPHABET;
  let decoded = 0n;
  let multi = 1n;
  const base = BigInt(alphabet.length);
  
  // Process from right to left
  for (let i = encoded.length - 1; i >= 0; i--) {
    const char = encoded[i];
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    decoded += BigInt(index) * multi;
    multi *= base;
  }
  
  // Count leading zeros
  let leadingZeros = 0;
  for (const char of encoded) {
    if (char === alphabet[0]) {
      leadingZeros++;
    } else {
      break;
    }
  }
  
  // Convert to bytes
  const hex = decoded.toString(16);
  const hexPadded = hex.length % 2 === 0 ? hex : '0' + hex;
  const bytes = new Uint8Array(leadingZeros + hexPadded.length / 2);
  
  // Fill leading zeros
  for (let i = 0; i < leadingZeros; i++) {
    bytes[i] = 0;
  }
  
  // Convert hex to bytes
  for (let i = 0; i < hexPadded.length; i += 2) {
    bytes[leadingZeros + i / 2] = parseInt(hexPadded.slice(i, i + 2), 16);
  }
  
  return bytes;
}

import type { ParsedDPoPKey } from './types';

/**
 * Parse a DPoP key from string format (JWK JSON or did:key multibase)
 */
export function parseDPoPKey(dpopKeyString: string): ParsedDPoPKey {
  // Check if it's a did:key format
  if (dpopKeyString.startsWith('did:key:')) {
    return parseDIDKey(dpopKeyString);
  }

  try {
    // Try parsing as JSON first (JWK format)
    const jwk = JSON.parse(dpopKeyString);
    if (jwk.kty && jwk.crv && jwk.x && jwk.y) {
      return jwk as ParsedDPoPKey;
    }
    throw new Error('Invalid JWK format');
  } catch (e) {
    throw new Error(`Unsupported DPoP key format: ${e}`);
  }
}

/**
 * Parse a DID key format (did:key:z...) into JWK format
 */
function parseDIDKey(didKey: string): ParsedDPoPKey {
  try {
    // Remove 'did:key:' prefix
    const keyPart = didKey.slice(8);
    
    if (!keyPart.startsWith('z')) {
      throw new Error('Only base58btc encoding (z prefix) is supported');
    }
    
    // Decode the base58btc multibase string
    const multibaseDecoded = decodeBase58btc(keyPart.slice(1)); // Remove 'z' prefix
    
    // Parse the multicodec prefix and key bytes
    const { codec, bytes } = parseMulticodecKey(multibaseDecoded);
    
    // Convert to JWK based on codec type
    switch (codec) {
      case 0x1200: // P-256 public key
        return parseP256PublicKey(bytes);
      case 0x1201: // P-384 public key  
        return parseP384PublicKey(bytes);
      case 0x1205: // secp256k1 public key
        return parseSecp256k1PublicKey(bytes);
      case 0x1306: // P-256 private key
        return parseP256PrivateKey(bytes);
      default:
        throw new Error(`Unsupported key codec: 0x${codec.toString(16)}`);
    }
  } catch (error) {
    throw new Error(`Failed to parse DID key: ${error}`);
  }
}

/**
 * Parse multicodec prefix and extract key bytes
 */
function parseMulticodecKey(data: Uint8Array): { codec: number; bytes: Uint8Array } {
  let offset = 0;
  let codec = 0;
  let shift = 0;
  
  // Parse varint multicodec prefix
  while (offset < data.length) {
    const byte = data[offset++];
    codec |= (byte & 0x7F) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  
  const bytes = data.slice(offset);
  return { codec, bytes };
}

/**
 * Convert P-256 public key bytes to JWK format
 */
function parseP256PublicKey(keyBytes: Uint8Array): ParsedDPoPKey {
  if (keyBytes.length === 33) {
    // Compressed format - decompress to get x,y coordinates
    return decompressP256Key(keyBytes);
  } else if (keyBytes.length === 65 && keyBytes[0] === 0x04) {
    // Uncompressed format
    const x = keyBytes.slice(1, 33);
    const y = keyBytes.slice(33, 65);
    
    return {
      kty: 'EC',
      crv: 'P-256',
      x: base64urlEncode(x),
      y: base64urlEncode(y),
    };
  } else {
    throw new Error(`Invalid P-256 key length: ${keyBytes.length}`);
  }
}

/**
 * Derive P-256 public key coordinates from private key using elliptic curve multiplication
 */
function deriveP256PublicKey(privateKeyBytes: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  // P-256 curve parameters
  const p = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  
  // P-256 generator point G
  const gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
  const gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
  
  // Convert private key to bigint
  const d = BigInt('0x' + Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  
  // Validate private key is in valid range
  if (d <= 0n || d >= n) {
    throw new Error('Invalid private key: out of valid range');
  }
  
  // Perform scalar multiplication: (x, y) = d * G
  const { x, y } = scalarMultiplyP256(d, gx, gy, p);
  
  // Convert coordinates back to 32-byte arrays
  const xBytes = bigIntToBytes(x, 32);
  const yBytes = bigIntToBytes(y, 32);
  
  return { x: xBytes, y: yBytes };
}

/**
 * Perform scalar multiplication on P-256 curve using double-and-add algorithm
 */
function scalarMultiplyP256(scalar: bigint, px: bigint, py: bigint, p: bigint): { x: bigint; y: bigint } {
  if (scalar === 0n) {
    throw new Error('Cannot multiply by zero');
  }
  
  // Point at infinity representation (we'll use null, but handle it carefully)
  let resultX = 0n;
  let resultY = 0n;
  let isInfinity = true;
  
  let addendX = px;
  let addendY = py;
  
  // Double-and-add algorithm
  while (scalar > 0n) {
    if (scalar & 1n) {
      // Add point to result
      if (isInfinity) {
        resultX = addendX;
        resultY = addendY;
        isInfinity = false;
      } else {
        const added = addPointsP256(resultX, resultY, addendX, addendY, p);
        resultX = added.x;
        resultY = added.y;
      }
    }
    
    // Double the addend point
    const doubled = doublePointP256(addendX, addendY, p);
    addendX = doubled.x;
    addendY = doubled.y;
    
    scalar >>= 1n;
  }
  
  if (isInfinity) {
    throw new Error('Result is point at infinity');
  }
  
  return { x: resultX, y: resultY };
}

/**
 * Add two points on P-256 curve
 */
function addPointsP256(x1: bigint, y1: bigint, x2: bigint, y2: bigint, p: bigint): { x: bigint; y: bigint } {
  if (x1 === x2 && y1 === y2) {
    return doublePointP256(x1, y1, p);
  }
  
  // Calculate slope: s = (y2 - y1) / (x2 - x1)
  const dx = (x2 - x1 + p) % p;
  const dy = (y2 - y1 + p) % p;
  const dxInv = modInverse(dx, p);
  const s = (dy * dxInv) % p;
  
  // Calculate result point
  const x3 = (s * s - x1 - x2 + 2n * p) % p;
  const y3 = (s * (x1 - x3) - y1 + 2n * p) % p;
  
  return { x: x3, y: y3 };
}

/**
 * Double a point on P-256 curve
 */
function doublePointP256(x: bigint, y: bigint, p: bigint): { x: bigint; y: bigint } {
  // Calculate slope: s = (3 * x^2 - 3) / (2 * y)
  // Note: P-256 has a = -3
  const numerator = (3n * x * x - 3n + p) % p;
  const denominator = (2n * y) % p;
  const denominatorInv = modInverse(denominator, p);
  const s = (numerator * denominatorInv) % p;
  
  // Calculate result point
  const x3 = (s * s - 2n * x + p) % p;
  const y3 = (s * (x - x3) - y + 2n * p) % p;
  
  return { x: x3, y: y3 };
}

/**
 * Calculate modular multiplicative inverse using extended Euclidean algorithm
 */
function modInverse(a: bigint, m: bigint): bigint {
  if (a < 0n) a = (a % m + m) % m;
  
  // Extended Euclidean Algorithm
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  
  if (oldR !== 1n) {
    throw new Error('Modular inverse does not exist');
  }
  
  return (oldS % m + m) % m;
}

/**
 * Convert P-256 private key bytes to JWK format
 */
function parseP256PrivateKey(keyBytes: Uint8Array): ParsedDPoPKey {
  if (keyBytes.length === 32) {
    // Raw private key bytes (32 bytes for P-256)
    const d = base64urlEncode(keyBytes);
    
    // Derive public key coordinates from private key for DPoP proof generation
    const { x, y } = deriveP256PublicKey(keyBytes);
    
    return {
      kty: 'EC',
      crv: 'P-256',
      d,
      x: base64urlEncode(x),
      y: base64urlEncode(y),
    };
  } else {
    throw new Error(`Invalid P-256 private key length: ${keyBytes.length}, expected 32 bytes`);
  }
}

/**
 * Convert P-384 public key bytes to JWK format
 */
function parseP384PublicKey(keyBytes: Uint8Array): ParsedDPoPKey {
  if (keyBytes.length === 97 && keyBytes[0] === 0x04) {
    // Uncompressed format
    const x = keyBytes.slice(1, 49);
    const y = keyBytes.slice(49, 97);
    
    return {
      kty: 'EC',
      crv: 'P-384',
      x: base64urlEncode(x),
      y: base64urlEncode(y),
    };
  } else {
    throw new Error(`Invalid P-384 key format or length: ${keyBytes.length}`);
  }
}

/**
 * Convert secp256k1 public key bytes to JWK format
 */
function parseSecp256k1PublicKey(keyBytes: Uint8Array): ParsedDPoPKey {
  if (keyBytes.length === 65 && keyBytes[0] === 0x04) {
    // Uncompressed format
    const x = keyBytes.slice(1, 33);
    const y = keyBytes.slice(33, 65);
    
    return {
      kty: 'EC',
      crv: 'secp256k1',
      x: base64urlEncode(x),
      y: base64urlEncode(y),
    };
  } else {
    throw new Error(`Invalid secp256k1 key format or length: ${keyBytes.length}`);
  }
}

/**
 * Decompress a P-256 compressed public key
 */
function decompressP256Key(compressedKey: Uint8Array): ParsedDPoPKey {
  if (compressedKey.length !== 33) {
    throw new Error('Invalid compressed key length');
  }
  
  const prefix = compressedKey[0];
  const x = compressedKey.slice(1);
  
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error('Invalid compressed key prefix');
  }
  
  // P-256 curve parameters
  const p = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
  const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
  
  // Convert x to bigint
  const xBig = BigInt('0x' + Array.from(x).map(b => b.toString(16).padStart(2, '0')).join(''));
  
  // Calculate y² = x³ - 3x + b (mod p)
  const ySquared = (xBig ** 3n - 3n * xBig + b) % p;
  
  // Calculate y using modular square root (Tonelli-Shanks algorithm would be needed for general case)
  // For P-256, we can use the fact that p ≡ 3 (mod 4), so y = ±(y²)^((p+1)/4) mod p
  const y = modPow(ySquared, (p + 1n) / 4n, p);
  
  // Choose the correct y based on the prefix
  const yFinal = (y % 2n) === BigInt(prefix % 2) ? y : p - y;
  
  // Convert back to bytes
  const yBytes = bigIntToBytes(yFinal, 32);
  
  return {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlEncode(x),
    y: base64urlEncode(yBytes),
  };
}

/**
 * Modular exponentiation: (base^exp) mod mod
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Convert bigint to bytes with specified length
 */
function bigIntToBytes(num: bigint, length: number): Uint8Array {
  const hex = num.toString(16).padStart(length * 2, '0');
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Base64url encode without padding
 */
function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a DPoP proof JWT for a given HTTP request
 * @param method HTTP method (GET, POST, etc.)
 * @param url Full URL of the request
 * @param dpopKey The DPoP private key (JWK format)
 * @param accessToken Optional access token for ath claim
 * @param nonce Optional DPoP nonce value from server
 */
export async function generateDPoPProof(
  method: string,
  url: string,
  dpopKey: ParsedDPoPKey,
  accessToken?: string,
  nonce?: string
): Promise<string> {
  try {
    // Validate the key has required fields
    if (!dpopKey.kty || !dpopKey.crv || !dpopKey.x || !dpopKey.y || !dpopKey.d) {
      throw new Error(`Invalid DPoP key format. Missing required fields. Got: ${JSON.stringify({
        kty: dpopKey.kty,
        crv: dpopKey.crv,
        x: !!dpopKey.x,
        y: !!dpopKey.y,
        d: !!dpopKey.d
      })}`);
    }

    // Determine algorithm based on curve
    const alg = dpopKey.crv === 'P-256' ? 'ES256' : 
                dpopKey.crv === 'P-384' ? 'ES384' : 
                dpopKey.crv === 'secp256k1' ? 'ES256K' : 'ES256';

    // Import the private key for signing - explicitly set algorithm
    const privateKeyJWK = {
      ...dpopKey,
      alg: alg,
      use: 'sig',
    };
    
    const privateKey = await importJWK(privateKeyJWK, alg);
    
    // Create public key JWK (without private components)
    const publicJWK = {
      kty: dpopKey.kty,
      crv: dpopKey.crv,
      x: dpopKey.x,
      y: dpopKey.y
    };

    // Generate unique JTI (JWT ID)
    const jti = randomBytes(16).toString('hex');
    
    // Current timestamp
    const iat = Math.floor(Date.now() / 1000) - 30;
   
    const exp = iat + 300;

    // Build the DPoP proof payload
    const payload: Record<string, any> = {
      jti,
      htm: method.toUpperCase(),
      htu: url,
      iat,
      exp,
    };

    // Add nonce if provided
    if (nonce) {
      payload.nonce = nonce;
    }

    // Add access token hash if provided
    if (accessToken) {
      // For simplicity, we'll use a basic hash - in production, use proper SHA-256
      const crypto = await import('crypto');
      const hash = crypto.createHash('sha256').update(accessToken).digest('base64url');
      payload.ath = hash;
    }

    // Create and sign the JWT
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: alg, // Use the determined algorithm
        jwk: publicJWK,
      })
      .sign(privateKey);

    return jwt;
  } catch (error) {
    throw new Error(`Failed to generate DPoP proof: ${error}`);
  }
}

/**
 * Create a mock DPoP key pair for testing (if needed)
 */
export async function createMockDPoPKeyPair(): Promise<{ publicKey: any; privateKey: ParsedDPoPKey }> {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  
  // Export keys to JWK format using jose's exportJWK function
  const publicJWK = await exportJWK(publicKey);
  const privateJWK = await exportJWK(privateKey);
  
  // Ensure the JWK has all required fields for P-256
  const parsedPrivateKey: ParsedDPoPKey = {
    kty: privateJWK.kty || 'EC',
    crv: privateJWK.crv || 'P-256',
    x: privateJWK.x as string,
    y: privateJWK.y as string,
    d: privateJWK.d as string, // Private key component
  };
  
  return {
    publicKey: publicJWK,
    privateKey: parsedPrivateKey,
  };
}