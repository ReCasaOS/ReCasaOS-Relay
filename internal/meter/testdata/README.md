`clients.json` is derived from tailscale.com v1.104.5 `derp/derpserver/debugclients.go` (`debugClientsJSON`,
`debugClient`, served by `Server.ServeDebugClients` at `/debug/clients/?all=1&format=json`). The e2e test
`TestDerperAdmission` decodes a real derper's `/debug/clients/` with the same parser (`meter.Derper.Clients`) in CI.
