 #
 # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 # SPDX-License-Identifier: MIT-0
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy of this
 # software and associated documentation files (the "Software"), to deal in the Software
 # without restriction, including without limitation the rights to use, copy, modify,
 # merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 # permit persons to whom the Software is furnished to do so.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 # PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
FROM debian

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y -qq --no-install-recommends \
      ca-certificates \
      git \
      wget && \
    mkdir -p /opt/bin && \
    mkdir -p /opt/src/github.com/aws-samples/inverting-proxy

ADD ./ /opt/src/github.com/aws-samples/inverting-proxy

RUN wget -O /opt/go1.14.2.linux-amd64.tar.gz \
      https://storage.googleapis.com/golang/go1.14.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf /opt/go1.14.2.linux-amd64.tar.gz && \
    export PATH=${PATH}:/usr/local/go/bin/:/opt/bin/ && \
    export GOPATH=/opt/ && \
    go get github.com/golang/groupcache/lru && \
    go get github.com/google/go-cmp/cmp && \
    go get github.com/google/uuid && \
    go get golang.org/x/net/context && \
    go get golang.org/x/net/publicsuffix && \
    go get golang.org/x/oauth2/google && \
    go get google.golang.org/api/compute/v1 && \
    go build -o ${GOPATH}/bin/proxy-forwarding-agent /opt/src/github.com/aws-samples/inverting-proxy/agent/agent.go && \
    rm -rf /opt/go1.4.2.linux-amd64.tar.gz && \
    rm -rf /usr/local

ENV DEBUG "false"
ENV PROXY ""
ENV PROXY_TIMEOUT "60s"
ENV BACKEND ""
ENV HOSTNAME "localhost"
ENV PORT "8080"
ENV SHIM_WEBSOCKETS "false"
ENV SHIM_PATH ""
ENV HEALTH_CHECK_PATH "/"
ENV HEALTH_CHECK_INTERVAL_SECONDS "0"
ENV HEALTH_CHECK_UNHEALTHY_THRESHOLD "2"
ENV SESSION_COOKIE_NAME ""
ENV FORWARD_USER_ID "false"
ENV REWRITE_WEBSOCKET_HOST "false"
ENV MONITORING_PROJECT_ID ""
ENV MONITORING_RESOURCE_LABELS ""
ENV METRIC_DOMAIN ""

CMD ["/bin/sh", "-c", "/opt/bin/proxy-forwarding-agent --debug=${DEBUG} --proxy=${PROXY} --proxy-timeout=${PROXY_TIMEOUT} --backend=${BACKEND} --host=${HOSTNAME}:${PORT} --shim-websockets=${SHIM_WEBSOCKETS} --shim-path=${SHIM_PATH} --health-check-path=${HEALTH_CHECK_PATH} --health-check-interval-seconds=${HEALTH_CHECK_INTERVAL_SECONDS} --health-check-unhealthy-threshold=${HEALTH_CHECK_UNHEALTHY_THRESHOLD} --session-cookie-name=${SESSION_COOKIE_NAME} --forward-user-id=${FORWARD_USER_ID} --rewrite-websocket-host=${REWRITE_WEBSOCKET_HOST} --monitoring-project-id=${MONITORING_PROJECT_ID} --monitoring-resource-labels=${MONITORING_RESOURCE_LABELS} --metric-domain=${METRIC_DOMAIN}"]
