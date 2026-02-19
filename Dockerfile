# ── Stage 1: Build the dashboard ──
FROM node:20-alpine AS dashboard-build

WORKDIR /app
COPY package.json ./
COPY scanner/package.json ./scanner/
COPY dashboard/package.json ./dashboard/
RUN npm install

COPY scanner/ ./scanner/
COPY dashboard/ ./dashboard/
RUN npm run build --workspace=dashboard

# ── Stage 2: Production image ──
FROM node:20-alpine

WORKDIR /app

# Copy package files and install production deps only
COPY package.json ./
COPY scanner/package.json ./scanner/
RUN npm install --workspace=scanner --omit=dev && npm install --omit=dev

# Copy scanner source
COPY scanner/ ./scanner/

# Copy built dashboard
COPY --from=dashboard-build /app/dashboard/dist ./dashboard/dist

# Copy hooks (for reference / local mounting)
COPY hooks/ ./hooks/

# Create data directory for scan results
RUN mkdir -p scanner/data

# Expose API port
EXPOSE 3001

# Start the API server (serves both API + static dashboard)
CMD ["node", "scanner/server.js"]
