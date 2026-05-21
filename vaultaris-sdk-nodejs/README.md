# Vaultaris SDK for Node.js

Native Node.js bindings for Vaultaris IAM platform, built with napi-rs for high performance.

## Installation

```bash
npm install @vaultaris/sdk
# or
yarn add @vaultaris/sdk
# or
pnpm add @vaultaris/sdk
```

## Quick Start

```javascript
const { VaultarisClient } = require('@vaultaris/sdk');

// Create a client
const client = new VaultarisClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'your-api-key',
  timeoutMs: 30000  // optional
});

// Validate a token
const validation = await client.validateToken('user-access-token');
if (validation.valid) {
  console.log(`User: ${validation.username}`);
  console.log(`Roles: ${validation.roles.join(', ')}`);
}

// Check a permission
const result = await client.checkPermission(
  'tenant-id',
  'user-id',
  'orders',
  'create'
);
if (result.allowed) {
  console.log('Permission granted');
}

// Batch permission check
const permissions = await client.checkPermissions(
  'tenant-id',
  'user-id',
  [
    { resource: 'orders', action: 'read' },
    { resource: 'orders', action: 'create' },
    { resource: 'users', action: 'delete' }
  ]
);
console.log(`All allowed: ${permissions.allAllowed}`);

// Get user info
const user = await client.getUser('tenant-id', 'user-id');
console.log(`User: ${user.username} (${user.email})`);

// Validate a session
const session = await client.validateSession('session-token');
if (session.valid) {
  console.log(`Session expires: ${session.expiresAt}`);
}
```

## Express Middleware

```javascript
const express = require('express');
const { VaultarisClient } = require('@vaultaris/sdk');

const app = express();
const vaultaris = new VaultarisClient({
  baseUrl: process.env.VAULTARA_URL,
  apiKey: process.env.VAULTARA_API_KEY
});

// Authentication middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const validation = await vaultaris.validateToken(token);
  if (!validation.valid) {
    return res.status(401).json({ error: validation.error || 'Invalid token' });
  }

  req.user = {
    id: validation.userId,
    username: validation.username,
    email: validation.email,
    roles: validation.roles
  };
  next();
};

// Permission middleware factory
const requirePermission = (resource, action) => async (req, res, next) => {
  const result = await vaultaris.checkPermission(
    req.headers['x-tenant-id'],
    req.user.id,
    resource,
    action
  );

  if (!result.allowed) {
    return res.status(403).json({ error: 'Permission denied' });
  }
  next();
};

// Usage
app.get('/orders', authenticate, requirePermission('orders', 'read'), (req, res) => {
  res.json({ orders: [] });
});

app.post('/orders', authenticate, requirePermission('orders', 'create'), (req, res) => {
  res.json({ created: true });
});
```

## TypeScript

TypeScript definitions are included. Just import and use:

```typescript
import { VaultarisClient, VaultarisConfig, TokenValidation } from '@vaultaris/sdk';

const config: VaultarisConfig = {
  baseUrl: 'http://localhost:8080',
  apiKey: 'your-api-key'
};

const client = new VaultarisClient(config);
const validation: TokenValidation = await client.validateToken('token');
```

## API Reference

### VaultarisClient

#### Constructor

```typescript
new VaultarisClient(config: VaultarisConfig)
```

**VaultarisConfig:**
- `baseUrl: string` - Vaultaris server URL
- `apiKey?: string` - API key for authentication
- `timeoutMs?: number` - Request timeout in milliseconds (default: 30000)

#### Methods

##### validateToken(token: string): Promise<TokenValidation>

Validates an access token and returns user information.

##### checkPermission(tenantId: string, userId: string, resource: string, action: string): Promise<PermissionCheck>

Checks if a user has permission to perform an action on a resource.

##### checkPermissions(tenantId: string, userId: string, permissions: Permission[]): Promise<BatchPermissionResponse>

Checks multiple permissions at once.

##### getUser(tenantId: string, userId: string): Promise<UserInfo>

Gets detailed user information.

##### validateSession(token: string): Promise<SessionValidation>

Validates a session token.

## Building from Source

```bash
# Install dependencies
npm install

# Build debug
npm run build:debug

# Build release
npm run build
```

## License

MIT OR Apache-2.0
