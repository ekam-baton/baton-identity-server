FROM rust:latest as builder

WORKDIR /usr/src/app
# Cache dependencies
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Build actual code
COPY . .
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/baton-identity-server /usr/local/bin/baton-identity-server
COPY --from=builder /usr/src/app/migrations /migrations

RUN useradd -m -u 1000 appuser
USER appuser

CMD ["baton-identity-server"]
