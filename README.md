# homenet

A self hosted dev network: local DNS, an HTTPS reverse proxy with a local CA,
device pairing, Docker based service hosting, and a policy engine, all
queryable live via NQL.

## Building

```sh
go build ./...
```

## Policies

Policies are written in NQL. See `policies/example.nql` for an example:

```sh
labnet policy apply policies/example.nql
labnet policy status
```
