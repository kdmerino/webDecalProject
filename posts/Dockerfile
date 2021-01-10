# YOUR CODE HERE
# You should be familiar with how to fill this out based on auth-service
FROM golang:latest

ADD . /go/src/github.com/BearCloud/fa20-project-dev/posts

WORKDIR /go/src/github.com/BearCloud/fa20-project-dev/posts

RUN go mod download

RUN go build -o main .

EXPOSE 80

ENTRYPOINT [ "./main" ]