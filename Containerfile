FROM rust:1.71 AS builder
WORKDIR /build
COPY . .
RUN rustup component add clippy
RUN cargo clippy
RUN cargo build --release


FROM gcr.io/distroless/cc-debian11:nonroot@sha256:880bcf2ca034ab5e8ae76df0bd50d700e54eb44e948877244b130e3fcd5a1d66
COPY --from=builder --chown=0:0 --chmod=0755 \
  /build/target/release/u2h /usr/local/bin/u2h
ENTRYPOINT ["/usr/local/bin/u2h"]
CMD ["help"]
