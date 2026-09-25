# homenet

A self hosted dev network: local DNS, an HTTPS reverse proxy with a local CA,
device pairing, Docker based service hosting, and a policy engine, all
queryable live via [NQL](https://github.com/abdowns/netdb-lang), a small JIT compiled query language.

## Setup

netdb-lang (NQL) is a separate project under `netdb-lang/`. Build it first:

```sh
brew install llvm cmake ninja
git clone https://github.com/abdowns/netdb-lang
cmake -B netdb-lang/build -G Ninja -DCMAKE_PREFIX_PATH=$(brew --prefix llvm)
cmake --build netdb-lang/build
```

Then build labnet:

```sh
export PKG_CONFIG_PATH=$PWD/netdb-lang/build
go build -o labnetd ./cmd/labnetd
go build -o labnet ./cmd/labnet
```

## Running

Requires a reachable Docker daemon.

```sh
./labnetd --host-ip 192.168.1.50 --docker-socket ~/.docker/run/docker.sock &

./labnet pair NNNNNN --name "my laptop" # code printed on first labnetd run
./labnet expose myapp http://127.0.0.1:5173 # proxy an already running service
./labnet up myapp ./path/to/app # build and run from a Dockerfile
./labnet ls
./labnet down myapp

./labnet status
./labnet q DnsQuery "upstream"
./labnet q HttpRequest "service == \"myapp\""

./labnet policy apply policies/example.nql
./labnet policy status
./labnet alerts
```

Dashboard: http://127.0.0.1:8080/

## Tests

```sh
export PKG_CONFIG_PATH=$PWD/netdb-lang/build
go test ./...
```
