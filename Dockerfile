FROM cr.yandex/mirror/library/golang:1.21

WORKDIR /app

COPY go.mod ./
RUN go mod download
RUN touch go.sum  

COPY . .

RUN go build -o app

CMD ["./app"]