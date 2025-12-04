const { KMSClient, SignCommand, GetPublicKeyCommand } = require('@aws-sdk/client-kms');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { derToJose } = require('ecdsa-sig-formatter');

const kmsClient = new KMSClient({ region: process.env.AWS_REGION || 'us-east-1' });
const KMS_KEY_ID = process.env.KMS_KEY_ID;

if (!KMS_KEY_ID) {
  throw new Error('KMS_KEY_ID environment variable is required. Please set it in Lambda function configuration.');
}

// Cache for public key and JWKS
let publicKeyCache = null;
let jwksCache = null;
let cacheExpiry = null;
const CACHE_TTL = 3600000; // 1 hour in milliseconds

/**
 * Get public key from KMS and cache it
 * Returns public key in PEM format
 */
async function getPublicKey() {
  const now = Date.now();
  
  if (publicKeyCache && cacheExpiry && now < cacheExpiry) {
    return publicKeyCache;
  }

  try {
    const command = new GetPublicKeyCommand({ KeyId: KMS_KEY_ID });
    const response = await kmsClient.send(command);
    
    if (!response.PublicKey) {
      throw new Error('Public key not found in KMS response');
    }

    // KMS returns public key in DER format (X.509 SubjectPublicKeyInfo)
    // Convert to PEM format
    const publicKeyDer = Buffer.from(response.PublicKey);
    const base64Key = publicKeyDer.toString('base64');
    
    // Split into 64-character lines for PEM format
    const formattedKey = base64Key.match(/.{1,64}/g).join('\n');
    
    // Create PEM formatted key
    publicKeyCache = `-----BEGIN PUBLIC KEY-----\n${formattedKey}\n-----END PUBLIC KEY-----`;
    cacheExpiry = now + CACHE_TTL;
    
    return publicKeyCache;
  } catch (error) {
    console.error('Error getting public key from KMS:', error);
    throw error;
  }
}

/**
 * Generate JWKS from public key
 */
async function generateJWKS() {
  const now = Date.now();
  
  if (jwksCache && cacheExpiry && now < cacheExpiry) {
    return jwksCache;
  }

  try {
    const publicKeyPem = await getPublicKey();
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const keyDetails = publicKey.asymmetricKeyDetails;
    
    // Extract key information in JWK format
    const jwk = publicKey.export({ format: 'jwk' });
    
    // Generate key ID from KMS key ID (use last part of ARN or key ID itself)
    let keyId = KMS_KEY_ID;
    if (KMS_KEY_ID.includes('/')) {
      keyId = KMS_KEY_ID.split('/').pop();
    } else if (KMS_KEY_ID.includes(':')) {
      // Handle ARN format: arn:aws:kms:region:account:key/key-id
      const parts = KMS_KEY_ID.split(':');
      if (parts.length > 0) {
        const lastPart = parts[parts.length - 1];
        keyId = lastPart.includes('/') ? lastPart.split('/').pop() : lastPart;
      }
    }
    
    // Determine algorithm based on key details
    let algorithm = 'RS256';
    if (keyDetails.namedCurve) {
      if (keyDetails.namedCurve === 'prime256v1') algorithm = 'ES256';
      else if (keyDetails.namedCurve === 'secp384r1') algorithm = 'ES384';
      else if (keyDetails.namedCurve === 'secp521r1') algorithm = 'ES512';
    } else if (keyDetails.modulusLength) {
      // RSA keys - all use RS256 regardless of key size
      algorithm = 'RS256';
    }
    
    // Build JWK entry
    const jwkEntry = {
      kty: jwk.kty,
      use: 'sig',
      kid: keyId,
      alg: algorithm
    };
    
    // Add RSA-specific fields
    if (jwk.n) jwkEntry.n = jwk.n;
    if (jwk.e) jwkEntry.e = jwk.e;
    
    // Add ECDSA-specific fields
    if (jwk.x) jwkEntry.x = jwk.x;
    if (jwk.y) jwkEntry.y = jwk.y;
    if (jwk.crv) jwkEntry.crv = jwk.crv;
    
    const jwks = {
      keys: [jwkEntry]
    };

    jwksCache = jwks;
    return jwks;
  } catch (error) {
    console.error('Error generating JWKS:', error);
    throw error;
  }
}

/**
 * Get algorithm from KMS key
 */
async function getKeyAlgorithm() {
  try {
    const publicKeyPem = await getPublicKey();
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const keyDetails = publicKey.asymmetricKeyDetails;
    
    if (keyDetails.namedCurve) {
      if (keyDetails.namedCurve === 'prime256v1') return 'ES256';
      if (keyDetails.namedCurve === 'secp384r1') return 'ES384';
      if (keyDetails.namedCurve === 'secp521r1') return 'ES512';
    }
    
    // Default to RS256 for RSA keys
    return 'RS256';
  } catch (error) {
    console.error('Error getting key algorithm:', error);
    return 'RS256'; // Default fallback
  }
}

/**
 * Convert ECDSA DER signature to JWT format (r, s)
 * 
 * AWS KMS for ECDSA keys returns signature in DER format (ASN.1 structure).
 * JWT/JOSE standard requires signature in "r || s" format (concatenation of two numbers).
 * 
 * For RSA keys, conversion is not needed - KMS returns signature in the correct format.
 */
function derToJoseSignature(derSignature, algorithm) {
  // For RSA keys, signature is already in the correct format
  if (!algorithm.startsWith('ES')) {
    return derSignature;
  }
  
  // For ECDSA, use library to convert DER -> JOSE
  // KMS returns: SEQUENCE { INTEGER r, INTEGER s } (DER format)
  // JWT requires: r || s (JOSE format, fixed length)
  try {
    const derBuffer = Buffer.from(derSignature);
    const joseBuffer = derToJose(derBuffer, algorithm);
    return joseBuffer;
  } catch (error) {
    console.error('Error converting DER signature to JOSE format:', error);
    throw new Error(`Failed to convert ECDSA signature: ${error.message}`);
  }
}

/**
 * Sign JWT token using KMS
 */
async function signJWT(payload) {
  try {
    // Get algorithm from key
    const algorithm = await getKeyAlgorithm();
    
    // Create JWT header
    const header = {
      alg: algorithm,
      typ: 'JWT'
    };

    // Encode header and payload
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const message = `${encodedHeader}.${encodedPayload}`;
    const messageBuffer = Buffer.from(message, 'utf-8');

    // Determine signing algorithm and message type for KMS
    let signingAlgorithm;
    let messageType;
    let digest;
    
    if (algorithm.startsWith('ES')) {
      // ECDSA: KMS signs the digest
      if (algorithm === 'ES256') {
        digest = crypto.createHash('sha256').update(messageBuffer).digest();
        signingAlgorithm = 'ECDSA_SHA_256';
      } else if (algorithm === 'ES384') {
        digest = crypto.createHash('sha384').update(messageBuffer).digest();
        signingAlgorithm = 'ECDSA_SHA_384';
      } else if (algorithm === 'ES512') {
        digest = crypto.createHash('sha512').update(messageBuffer).digest();
        signingAlgorithm = 'ECDSA_SHA_512';
      }
      messageType = 'DIGEST';
    } else {
      // RSA: KMS signs the digest
      if (algorithm === 'RS256') {
        digest = crypto.createHash('sha256').update(messageBuffer).digest();
        signingAlgorithm = 'RSASSA_PKCS1_V1_5_SHA_256';
      } else if (algorithm === 'RS384') {
        digest = crypto.createHash('sha384').update(messageBuffer).digest();
        signingAlgorithm = 'RSASSA_PKCS1_V1_5_SHA_384';
      } else if (algorithm === 'RS512') {
        digest = crypto.createHash('sha512').update(messageBuffer).digest();
        signingAlgorithm = 'RSASSA_PKCS1_V1_5_SHA_512';
      } else {
        // Default to RS256
        digest = crypto.createHash('sha256').update(messageBuffer).digest();
        signingAlgorithm = 'RSASSA_PKCS1_V1_5_SHA_256';
      }
      messageType = 'DIGEST';
    }

    // Sign using KMS
    const signCommand = new SignCommand({
      KeyId: KMS_KEY_ID,
      Message: digest,
      MessageType: messageType,
      SigningAlgorithm: signingAlgorithm
    });

    const signResponse = await kmsClient.send(signCommand);
    
    if (!signResponse.Signature) {
      throw new Error('Signature not returned from KMS');
    }

    // Convert signature to JWT format
    let signature;
    if (algorithm.startsWith('ES')) {
      // ECDSA: convert DER to JOSE format
      signature = derToJoseSignature(signResponse.Signature, algorithm);
    } else {
      // RSA: use as-is
      signature = signResponse.Signature;
    }
    
    // Encode signature
    const encodedSignature = Buffer.from(signature).toString('base64url');
    
    // Return complete JWT
    return `${message}.${encodedSignature}`;
  } catch (error) {
    console.error('Error signing JWT with KMS:', error);
    throw error;
  }
}

/**
 * Verify JWT token (basic verification without signature check)
 */
function verifyJWT(token) {
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      throw new Error('Invalid JWT token');
    }
    return decoded;
  } catch (error) {
    console.error('Error verifying JWT:', error);
    throw error;
  }
}

/**
 * Main Lambda handler
 */
exports.handler = async (event) => {
  console.log('Received event:', JSON.stringify(event, null, 2));

  // Support both API Gateway and Function URL formats
  const path = event.rawPath || event.path || event.requestContext?.http?.path || event.requestContext?.path || '';
  const httpMethod = event.requestContext?.http?.method || event.httpMethod || event.requestContext?.httpMethod || event.requestContext?.requestContext?.http?.method || '';
  
  // For Function URL, also check headers directly
  const headers = event.headers || {};

  // Handle JWKS endpoint
  if (httpMethod === 'GET' && (path === '/.well-known/jwks.json' || path === '/jwks')) {
    try {
      const jwks = await generateJWKS();
      return {
        statusCode: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization'
        },
        body: JSON.stringify(jwks)
      };
    } catch (error) {
      console.error('Error generating JWKS:', error);
      return {
        statusCode: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({ error: 'Failed to generate JWKS', message: error.message })
      };
    }
  }

  // Handle signing endpoint
  if ((httpMethod === 'POST' || httpMethod === 'post') && (path === '/sign' || path === '/' || path === '')) {
    try {
      // Get Authorization header (support different header formats)
      const authHeader = headers.Authorization || 
                        headers.authorization || 
                        headers['Authorization'] ||
                        headers['authorization'] ||
                        event.headers?.Authorization || 
                        event.headers?.authorization || 
                        event.headers?.['authorization'];
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return {
          statusCode: 401,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          },
          body: JSON.stringify({ error: 'Missing or invalid Authorization header' })
        };
      }

      // Extract and verify JWT token
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix
      const decodedToken = verifyJWT(token);

      // Parse request body (support both formats)
      let body;
      if (event.body) {
        if (typeof event.body === 'string') {
          try {
            body = JSON.parse(event.body);
          } catch (e) {
            body = {};
          }
        } else {
          body = event.body;
        }
      } else {
        body = {};
      }

      if (!body || !body.payload) {
        return {
          statusCode: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          },
          body: JSON.stringify({ error: 'Missing payload in request body' })
        };
      }

      // Prepare JWT payload with original claims
      // Don't override exp if it's already set in payload
      const payload = {
        ...body.payload
      };
      
      // Add iat if not present
      if (!payload.iat) {
        payload.iat = Math.floor(Date.now() / 1000);
      }
      
      // Add exp if not present (default 1 hour)
      if (!payload.exp) {
        payload.exp = Math.floor(Date.now() / 1000) + 3600;
      }

      // Sign the JWT with KMS
      const signedToken = await signJWT(payload);

      return {
        statusCode: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization'
        },
        body: JSON.stringify({
          id_token: signedToken
        })
      };
    } catch (error) {
      console.error('Error processing signing request:', error);
      return {
        statusCode: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({ 
          error: 'Failed to sign JWT token', 
          message: error.message 
        })
      };
    }
  }

  // Handle OPTIONS for CORS
  if (httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400'
      },
      body: ''
    };
  }

  // 404 for unknown paths
  return {
    statusCode: 404,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    },
    body: JSON.stringify({ error: 'Not found' })
  };
};

