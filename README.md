# pounce-sync

Self-hosted, end-to-end encrypted sync server for the [pounce](https://github.com/catgirl-systems/pounce-ios) iOS SSH client. It stores only ciphertext: it verifies signatures and preconditions, assigns sequence numbers and stores bytes, and contains no decryption code. One static binary, one SQLite file.

## Build

```sh
direnv allow            # or: nix-shell
go build ./cmd/pounce-sync
```

or with Docker:

```sh
docker build -t pounce-sync .
```

## Configure

All configuration is read from `pounce-sync.toml` in the working directory, or the file given with `-config`. Unknown keys are errors.

```toml
origin = "https://sync.example.org"
# db = "pounce-sync.db"
# listen = ":8080"
# registration = "invite"
```

| Key | Default | Meaning |
|---|---|---|
| `origin` | required | Public origin clients use, exactly, such as `https://sync.example.org`; it is bound into login signatures |
| `db` | `"pounce-sync.db"` | SQLite file, relative to the working directory |
| `listen` | `":8080"` | Listen address |
| `registration` | `"invite"` | `open`, `invite` or `closed` |
| `tls_cert`, `tls_key` | unset | Serve HTTPS directly; set both or neither |
| `max_records` | `10000` | Records per account |
| `rate_ip` | `60` | Requests per minute per client IP (IPv6 per /64) on unauthenticated endpoints, and separately for failed authentications |
| `rate_device` | `600` | Requests per minute per device session |
| `real_ip_header` | unset | Client IP header, such as `"X-Real-IP"`; only set it behind a proxy that overwrites it |

Without `tls_cert`, run it behind a TLS-terminating reverse proxy: clients only speak HTTPS.

## Run

```sh
./pounce-sync serve               # or: ./pounce-sync -config /etc/pounce-sync.toml serve
./pounce-sync invite -ttl 72h     # prints an invite token for a new account
./pounce-sync stats               # accounts, records, stored bytes
```

With Docker, the working directory is `/data`, so the config and the database both live there:

```sh
docker run -d -p 8080:8080 -v pounce-data:/data -v ./pounce-sync.toml:/data/pounce-sync.toml:ro pounce-sync
docker exec <container> /pounce-sync invite
```

## Backup

```sh
./pounce-sync backup /backups/pounce-sync-$(date +%F).db
```

This writes a consistent copy (`VACUUM INTO`) while the server keeps running. The database holds only ciphertext and public keys, so the copy can be stored anywhere. Restore by stopping the server and replacing the `db` file with the copy.
