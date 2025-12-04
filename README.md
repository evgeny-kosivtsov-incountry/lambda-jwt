# InCountry JWT Signing Lambda Function

AWS Lambda function for signing JWT tokens with AWS KMS and providing JWKS endpoint.

## Description

This Lambda function is designed for use in InCountry.com integration with Auth0 and other IDPs. It allows customers (e.g., Siemens) to sign JWT tokens with their own keys stored in AWS KMS instead of using InCountry's key.

## Features

1. **JWT Token Signing** - Accepts uncloaked claims and signs them with a key from AWS KMS
2. **JWKS Endpoint** - Provides public keys in JWKS format for signature validation

## Requirements

- Node.js 18.x or higher (tested with Node.js 24.x)
- AWS Account with configured KMS key
- AWS Lambda function with appropriate IAM permissions

## Installation

1. Install dependencies:
```bash
npm install
```

2. Create ZIP archive for deployment:
```bash
zip -r function.zip index.js package.json node_modules/
```

## Configuration

### Lambda Environment Variables

- `KMS_KEY_ID` (required) - KMS key ID or ARN for signing
- `AWS_REGION` (optional) - AWS region (default: us-east-1)

### IAM Permissions

The Lambda function requires the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:*:*:key/<KMS_KEY_ID>"
    }
  ]
}
```

### KMS Key Configuration

The KMS key must be:
- Asymmetric key (RSA or ECDSA)
- Key usage: Sign and Verify
- For RSA: recommended RS256 (2048, 3072, or 4096 bits)
- For ECDSA: ES256 (prime256v1), ES384 (secp384r1), or ES512 (secp521r1)

## API Endpoints

### POST /sign (or POST /)

Signs JWT token with provided claims.

**Request:**
```
POST /sign
Authorization: Bearer <jwt_token_with_cloaked_claims>
Content-Type: application/json

{
  "payload": {
    "sub": "user123",
    "email": "user@example.com",
    "name": "John Doe",
    ...
  }
}
```

**Response:**
```json
{
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### GET /.well-known/jwks.json (or GET /jwks)

Returns JWKS (JSON Web Key Set) for validating signed tokens.

**Request:**
```
GET /.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

## Deployment

### Using AWS Console

1. Create Lambda function with Node.js 24.x runtime
2. Upload `function.zip` as deployment package
3. Set environment variables: `KMS_KEY_ID` and `AWS_REGION`
4. Configure IAM role with KMS permissions
5. Create Function URL with CORS enabled

See `DEPLOY.md` for detailed instructions.

### Using AWS CLI

```bash
aws lambda create-function \
  --function-name incountry-jwt-signing \
  --runtime nodejs24.x \
  --role arn:aws:iam::ACCOUNT_ID:role/lambda-kms-role \
  --handler index.handler \
  --zip-file fileb://function.zip \
  --environment Variables="{KMS_KEY_ID=your-kms-key-id,AWS_REGION=us-east-1}" \
  --timeout 30 \
  --memory-size 256
```

### Using AWS SAM

See `template.yaml` for SAM template configuration.

### Using Serverless Framework

See `serverless.yml` for Serverless Framework configuration.

## Usage with InCountry Proxy

Configure InCountry proxy to use this endpoint:

```json
{
  "collections": [
    {
      "name": "f8e7d985-7e29-4ed1-bb4e-c36fb6d2c1d5",
      "collectionPath": "$.id_token",
      "collectionLocation": "body",
      "entityIdNewPath": "$.sub",
      "entityIdPath": ["$.email", "$.sub"],
      "globalEntityId": true,
      "entityErrorCorrectionFieldPath": "$.name",
      "strategies": [
        {
          "path": "$.email"
        }
      ]
    }
  ],
  "plugin": "jwt",
  "method": "POST",
  "path": "/oauth/token",
  "externalSigningEndpoint": "https://your-lambda-url.lambda-url.region.on.aws/sign",
  "jwksEndpoint": "https://your-lambda-url.lambda-url.region.on.aws/.well-known/jwks.json"
}
```

## Testing

### Test JWKS Endpoint

```bash
curl https://your-function-url.lambda-url.region.on.aws/.well-known/jwks.json
```

### Test Signing Endpoint

```bash
curl -X POST https://your-function-url.lambda-url.region.on.aws/sign \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test" \
  -H "Content-Type: application/json" \
  -d '{"payload":{"sub":"user123","email":"user@example.com"}}'
```

See `TESTING.md` for detailed testing instructions.

## Error Handling

The function returns the following HTTP status codes:

- `200` - Success
- `400` - Bad Request (missing payload)
- `401` - Unauthorized (missing or invalid Authorization header)
- `404` - Not Found (endpoint not found)
- `500` - Internal Server Error

## Security

- JWT token from Authorization header is validated (basic structure check)
- KMS key never leaves AWS KMS
- Public keys are cached for 1 hour for performance
- CORS is configured for InCountry proxy integration

## Supported Algorithms

- **RSA**: RS256, RS384, RS512
- **ECDSA**: ES256, ES384, ES512

Algorithm is automatically determined based on KMS key type and size.

## Performance and Limits

- Timeout: recommended 30 seconds
- Memory: recommended 256 MB
- Public key caching: 1 hour
- CORS support for all origins (can be restricted if needed)

## Troubleshooting

### Error: "KMS_KEY_ID environment variable is required"
Ensure the `KMS_KEY_ID` environment variable is set in Lambda configuration.

### Error: "AccessDenied" when calling KMS
Check IAM permissions for Lambda function. It must have `kms:Sign` and `kms:GetPublicKey` permissions for the specified key.

### Invalid JWT signature
Ensure:
- KMS key supports the selected signing algorithm
- Correct format is used for ECDSA (DER to JOSE conversion)

## How It Works

1. **Signing Flow:**
   - InCountry Proxy receives JWT from Auth0 (with cloaked claims)
   - Proxy uncloaks the claims
   - Proxy calls Lambda `/sign` endpoint with uncloaked claims in body
   - Lambda signs the claims using KMS key
   - Lambda returns signed JWT token

2. **JWKS Flow:**
   - Any service can request public key via `/.well-known/jwks.json`
   - Lambda retrieves public key from KMS
   - Returns JWKS format for token validation

## License

ISC
