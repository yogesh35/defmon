# Frontend React + Vite multi-stage Docker build

# Stage 1: Build the optimized static assets
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first for Docker caching
COPY package.json package-lock.json ./
RUN npm ci

# Copy the rest of the application
COPY . .

# Build the Vite application
RUN npm run build

# Stage 2: Serve strictly bounded HTTP chunks via NGINX
FROM nginx:alpine

# Remove default NGINX configuration allowing full fallback SPA routing
RUN rm -rf /usr/share/nginx/html/*

# Copy built artifacts from Stage 1
COPY --from=builder /app/dist /usr/share/nginx/html

# Map custom NGINX fallback logic and proxy API traffic to backend service
RUN echo $'server {\n\
    listen 80;\n\
    location / {\n\
        root /usr/share/nginx/html;\n\
        index index.html;\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
    location /api/ {\n\
        proxy_pass http://defmon-api:8000;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header Host $host;\n\
        proxy_set_header X-Real-IP $remote_addr;\n\
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
        proxy_set_header X-Forwarded-Proto $scheme;\n\
        proxy_set_header Upgrade $http_upgrade;\n\
        proxy_set_header Connection "upgrade";\n\
    }\n\
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
