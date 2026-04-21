# Sentinel

Sentinel is a hardened zero-trust bastion platform for audited ingress into private infrastructure.

## Repository Layout

- `backend/`: Go services for API and SSH bastion core.
- `frontend/`: React + Tailwind admin console.

## Quick Start

### Backend

```bash
cd backend
go run ./cmd/sentinel-api
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```
