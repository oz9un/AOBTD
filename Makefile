.PHONY: build run clean test bench-juice-snapshot bench-juice-diff

BINARY=aobtd
VERSION=0.1.0-dev

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY).exe ./cmd/aobtd

run: build
	./$(BINARY).exe $(ARGS)

test:
	go test ./... -v

bench-juice-snapshot:
	python3 bench/juice_coverage.py snapshot --target $${JUICE_TARGET:-http://127.0.0.1:3000} --out $${OUT:-/tmp/aobtd-juice-snapshot.json}

bench-juice-diff:
	python3 bench/juice_coverage.py diff --before $${BEFORE:?set BEFORE=/path/before.json} --after $${AFTER:?set AFTER=/path/after.json} --format $${FORMAT:-markdown}

clean:
	rm -f $(BINARY).exe
	rm -rf aobtd-output/

lint:
	go vet ./...
