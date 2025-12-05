FROM cgr.dev/chainguard/go@sha256:5f82c8798f19224b7d4bda0f05ea0f5adae5f122514a9d4f8e2de61411a97308 AS builder

WORKDIR /app
COPY . /app

RUN go version; \
    go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:1596d00da637ed14b64d1652cf553df9b108d56ae515fbfe662af7f084e7e7d8

WORKDIR /app

COPY --from=builder /app/main .

ENV ARANGO_HOST localhost
ENV ARANGO_USER root
ENV ARANGO_PASS rootpassword
ENV ARANGO_PORT 8529

EXPOSE 8080

ENTRYPOINT [ "/app/main" ]
