# Static build of the web app served by nginx (for docker compose; production uses Vercel).
# Build context: repository root.
FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY frontend ./frontend
RUN pnpm install --frozen-lockfile
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN pnpm -F @quantumtrace/web build

FROM nginx:1.27-alpine
COPY frontend/apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /repo/frontend/apps/web/dist /usr/share/nginx/html
EXPOSE 8080
