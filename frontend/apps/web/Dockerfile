# Static build of the web app served by nginx (for docker compose; production uses Vercel).
# Build context: repository root.
FROM node:25-alpine AS build
WORKDIR /repo
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# Node 25+ no longer bundles corepack: install the pnpm pinned in package.json's packageManager.
RUN npm install -g "$(node -p "require('./package.json').packageManager")"
COPY frontend ./frontend
COPY extensions ./extensions
# The VS Code extension the site offers for download ships the Python tracer from the backend.
COPY backend/src/quantumtrace/tracers/python ./backend/src/quantumtrace/tracers/python
RUN pnpm install --frozen-lockfile
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN pnpm -F @quantumtrace/web build

FROM nginx:1.31-alpine
COPY frontend/apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /repo/frontend/apps/web/dist /usr/share/nginx/html
EXPOSE 8080
