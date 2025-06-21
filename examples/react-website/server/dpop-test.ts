#!/usr/bin/env tsx
/**
 * Test script for DID key parsing functionality
 * 
 * Usage: npx tsx server/dpop-test.ts
 */

import { parseDPoPKey } from './dpop';

// Example DID keys for testing
const testKeys = [
  // P-256 compressed public key example
  'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169',
  
  // Unsupported codec example (should fail)
  'did:key:z4oJ8bKmG7nCg7UjCgj7pV3YHHT3fGd8vUpUNYKpKbN1HuE',
  
  // P-256 private key example (0x1306 codec)
  // This is a synthetic example - in practice this would come from AIP
  'did:key:z42tj7NhHpAFVd5rSVF8SKhRwfXbStJjjkfEs4Hm5wuxx3b5',
  
  // JWK format (should still work)
  '{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}',
];

console.log('🧪 Testing DID Key Parsing\n');

for (const [index, keyString] of testKeys.entries()) {
  console.log(`Test ${index + 1}:`);
  console.log(`Input: ${keyString.substring(0, 60)}${keyString.length > 60 ? '...' : ''}`);
  
  try {
    const parsed = parseDPoPKey(keyString);
    console.log(`✅ Parsed successfully:`);
    console.log(`   Key Type: ${parsed.kty}`);
    console.log(`   Curve: ${parsed.crv}`);
    if (parsed.x) {
      console.log(`   X coordinate: ${parsed.x.substring(0, 20)}...`);
    }
    if (parsed.y) {
      console.log(`   Y coordinate: ${parsed.y.substring(0, 20)}...`);
    }
    if (parsed.d) {
      console.log(`   Private key: ${parsed.d.substring(0, 20)}...`);
    }
  } catch (error) {
    console.log(`❌ Parsing failed: ${error}`);
  }
  
  console.log('');
}

console.log('📋 Supported formats:');
console.log('  • did:key:z... (P-256, P-384, secp256k1 with base58btc encoding)');
console.log('  • P-256 private keys (0x1306 codec)');
console.log('  • JWK JSON format');
console.log('  • Both compressed and uncompressed public keys');