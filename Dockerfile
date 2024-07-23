FROM ghcr.io/gleam-lang/gleam:v1.3.1-erlang-alpine AS build
WORKDIR /src
COPY . .
RUN gleam export erlang-shipment

FROM erlang:alpine
COPY --from=build /src/build/erlang-shipment /app
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh", "run"]
CMD []
