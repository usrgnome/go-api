build:
	@go build -o bin/gobank

run: build
	@./bin/gobank

test:
	@go test -v ./...

db:
	docker stop some-postgres
	docker rm some-postgres
	docker run --name some-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 5432:5432 -d postgres 