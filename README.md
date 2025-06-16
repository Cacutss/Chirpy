# Chirpy
Chirpy is a server that works alike social media applications, having users, posts (chirps) and even security related measures, such as password encryption with [bcrypt](https://golang.org/x/crypto/bcrypt) and JWT (Json Web Tokens) for authorization.
## Why?
First of all, to have a better understanding of how http servers work, things like:
* Headers
* Error codes
* URL Queries
* Apis
* Webhooks
## Installation
You will need go 1.3.4 or later, you can install go trough the [official instructions](https://go.dev/doc/install) or trough webi:
### Windows
```
curl.exe https://webi.ms/golang | powershell
```
### Linux
```
curl -sS https://webi.sh/golang | sh; \
source ~/.config/envman/PATH.env
```
Then you're gonna want to clone this repo wherever you want, with go you can either run the server
```
go run main.go
```
or build it and run the executable
```
go build main.go
```
