# Deployment & Setup Guide

## Current Issue: 404 on /api/xrpc-proxy

The issue you're seeing is that the React app is running on Vite dev server (port 3002) but trying to call the BFF server endpoints which only exist when running the production BFF server.

## Quick Fix

**Option 1: Use BFF Server (Recommended for testing XRPC)**

```bash
# 1. Build the React app
npm run build

# 2. Start the BFF server (serves React app + API endpoints)
npm run server:dev

# 3. Open http://localhost:3001 (NOT 3002)
```

**Option 2: Use Development Mode (For React development)**

```bash
# 1. Update .env to point to development API server
echo "VITE_DEMO_BASE_URL=http://localhost:3002" > .env

# 2. Start Vite dev server
npm run dev

# 3. In another terminal, start BFF server on different port
PORT=3001 npm run server:dev

# 4. Open http://localhost:3002
```

## Architecture

- **Port 3001**: BFF Server (production mode) - serves built React app + API endpoints
- **Port 3002**: Vite Dev Server (development mode) - serves React app with hot reload
- **Port 8080**: AIP Server (or use https://aipdev.tunn.dev)

## Current Configuration

Based on your .env file:
- AIP_BASE_URL: `https://aipdev.tunn.dev`
- DEMO_BASE_URL: `http://localhost:3001`

This means OAuth redirects expect the app to be running on port 3001 (BFF server), not 3002 (Vite dev server).

## Environment Variables

Create/update `.env` file:

```bash
# For production BFF server
VITE_AIP_BASE_URL=https://aipdev.tunn.dev
VITE_DEMO_BASE_URL=http://localhost:3001

# For development mode
VITE_AIP_BASE_URL=https://aipdev.tunn.dev  
VITE_DEMO_BASE_URL=http://localhost:3002
AIP_BASE_URL=https://aipdev.tunn.dev
PORT=3001
```