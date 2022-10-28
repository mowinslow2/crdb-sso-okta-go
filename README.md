# crdb-sso-okta-go

This repository contains a simple Go CRUD app that uses tokens retrieved from Okta to connect to CockroachDB. 

For more details on the code, OKTA setup, and CockroachDB refer to [this blog](https://morgans-blog.deno.dev/sso_dedicated_okta_golang)

## Variables Required

### Env Variables 

Set the following variables in your terminal: 

```
export OKTA_URL=<https://dev-number.okta.com/oauth2/v1/token>
export CLIENT_ID=<Okta Client ID>
export CLIENT_SECRET=<Okta Client Secret>
export OKTA_USERNAME=<Okta user>
export PASSWORD=<Okta password>
```

### Program Variables

The following three variables should be updated  in the `executeWorkload()` func to create your CockroachDB connection string

```
sqlUser := "sqlUser"
host := "host"
cert := "/ca.cert"
```

## Run 
`go mod init main.go && go mod tidy`

`go run main.go`