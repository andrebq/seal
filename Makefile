.PHONY: build tidy precommit dist


build:
	go build .

tidy:
	go fmt ./...
	go mod tidy

dist:
	go build -o dist/seal .
	go install

precommit: build tidy

watch:
	modd
