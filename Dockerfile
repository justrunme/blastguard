FROM gcr.io/distroless/static-debian12:nonroot

COPY blastguard /usr/local/bin/blastguard

ENTRYPOINT ["/usr/local/bin/blastguard"]
