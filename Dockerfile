FROM node:20-alpine

# Create app directory
WORKDIR /app

# Install dependencies first (for better caching)
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY src/ ./src/

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 -G nodejs
    USER nodejs

    # Expose port
    EXPOSE 3000

    # Health check
    HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
        CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

        # Start the server
        CMD ["node", "src/server.js"]
