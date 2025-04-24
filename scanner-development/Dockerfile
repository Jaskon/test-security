ARG OXVIID=v0
FROM node:18.16.0 as build
## scanner application
WORKDIR /app
COPY src /app/src
COPY package.json /app/package.json
COPY package-lock.json /app/package-lock.json
COPY tsconfig.json /app/tsconfig.json
COPY start.sh /app/start.sh
COPY .npmrc /app/.npmrc
RUN npm ci && \
    npm run build && \
    cp -R /app/build/* /app/src && \
    rm -rf /app/node_modules/prettier \
    /app/node_modules/npm \
    /app/node_modules/typescript \
    /app/node_modules/@types \
    /app/node_modules/@jest \
    /app/node_modules/@babel \
    /app/build \
    /app/ox-security

FROM node:18.16.0-alpine3.17 as production
ARG OXVIID
WORKDIR /app
RUN apk add --no-cache git=2.38.5-r0 gcompat=1.1.0-r0 openssh=9.1_p1-r5

## ssh connectivity stuff
# enable ssh between containers by adding required files
COPY docker_ssh /root/.ssh
# ensure proper permissions on files
RUN chmod 600 /root/.ssh/id_rsa && \
    chmod 644 /root/.ssh/id_rsa.pub && \
    chmod 644 /root/.ssh/config
# copy app from builder image
COPY --from=build /app /app
# We are doing a lot of IO (https://nodejs.org/api/cli.html#uv_threadpool_sizesize)
ENV UV_THREADPOOL_SIZE=128
# configure CMD to use the start script
CMD [ "node", "--max-old-space-size=16384", "/app/src/index.js" ]
# expose port for when working in server mode
EXPOSE 5000
## final touches
# copy the version file from the build env (pipeline)
# DEPRECATION: stop using /app/version.json and use /var/version.json instead (to align with other containers and best-practice)
COPY version.json /app/version.json
COPY version.json /var/version.json
# add a support label to direct users to support channel
LABEL support=support@ox.security
LABEL OXVIID=$OXVIID
