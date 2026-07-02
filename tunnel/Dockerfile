# syntax=docker/dockerfile:1
#
# Internal guacamole-lite tunnel. Never internet-facing: the baremetal data
# plane forward-auths and single-use-consumes the grant, then reverse-proxies
# the WebSocket to this service, which decrypts the token and bridges to guacd.
# Build context is ./tunnel.

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app/tunnel

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./

USER node
EXPOSE 8600
CMD ["node", "server.js"]
