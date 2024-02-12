FROM docker.io/rust:1.71@sha256:c2eb45e99c89a67bcec8b30304afdb73405ea55b8a6cdafd8a1e2cfcf43a2ec2 AS builder
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
