# google-credential-guard

Validate Google service-account JSON supplied by an external party before using it in a Google SDK. This module intentionally accepts only service-account keys. It does not accept arbitrary ADC or Workload Identity Federation configurations.

```go
key, err := googlecredentialguard.ParseServiceAccountJSON(uploadedJSON)
if err != nil { return err }
opt, err := key.ClientOption()
if err != nil { return err }
client, err := bigquery.NewClient(ctx, projectID, opt)
```

`ParseServiceAccountJSON` enforces a 64 KiB limit, rejects duplicate and unsupported fields, checks the service-account key and email, and pins the OAuth token endpoint. `CanonicalJSON()` returns a copy for APIs that only accept bytes; prefer the type-specific adapters. No method reads a file or makes a network request. Validate at both configuration admission and use time so stored legacy configurations are covered.

For a separately authorized local file path, the caller should read it with a size bound before parsing. Never pass a tenant-selected path to a server-side file reader. Explicit Application Default Credentials, if needed, are a distinct auth mode and are not selected by this JSON parser.
