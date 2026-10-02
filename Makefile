FRONT=frontend
DIST=$(FRONT)/dist
EMBED=cmd/checker/dist

.PHONY: all front back build run clean

all: build

front:
	cd $(FRONT) && npm install && npm run build
	rm -rf $(EMBED)
	cp -r $(DIST) $(EMBED)

back:
	go build -o bin/checker ./cmd/checker

build: front back

run:
	PORT=18080 NO_BROWSER=1 go run ./cmd/checker

clean:
	rm -rf $(DIST) $(EMBED) bin
