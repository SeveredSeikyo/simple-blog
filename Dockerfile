# Use Node.js 18 LTS as base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Create app user for security
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Create necessary directories
RUN mkdir -p images && chown nodejs:nodejs images
RUN mkdir -p data && chown nodejs:nodejs data

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev && npm cache clean --force

# Copy application files
COPY --chown=nodejs:nodejs . .

# Ensure proper permissions for database file
RUN touch sqlite.db && chown nodejs:nodejs sqlite.db

# Switch to non-root user
USER nodejs

# Expose port 3020
EXPOSE 3020

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3020/api/all', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

# Start the application
CMD ["node", "app.js"]