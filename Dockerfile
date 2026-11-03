FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /enrolment ./cmd/enrolment

FROM gcr.io/distroless/static-debian12
COPY --from=build /enrolment /enrolment
EXPOSE 8081
ENTRYPOINT ["/enrolment"]
