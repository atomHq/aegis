# Aegis Go SDK

```bash
go get github.com/oluwasemilore/aegis-go
```

```go
package main

import (
	"context"
	"fmt"

	"github.com/oluwasemilore/aegis-go/aegis"
)

func main() {
	client := aegis.NewClient("aegis_sk_live_...", aegis.WithBaseURL("http://localhost:8080"))

	project, err := client.CreateProject(context.Background(), aegis.CreateProjectInput{
		Name: "Backend", Slug: "backend", Environment: "production",
	})
	if err != nil {
		panic(err)
	}

	_, _ = client.PutSecret(context.Background(), project.ID, aegis.PutSecretInput{
		Key: "DATABASE_URL", Value: "postgres://prod:secret@example/db",
	})

	secret, _ := client.GetSecret(context.Background(), project.ID, "DATABASE_URL")
	fmt.Println(secret.Value)
}
```

API key management endpoints are JWT-authenticated in the Aegis API:

```go
client := aegis.NewClient("", aegis.WithAuthToken("eyJ..."))
created, err := client.CreateAPIKey(ctx, aegis.CreateAPIKeyInput{
	Name: "CI read only",
	Scopes: []string{aegis.ScopeSecretsRead},
})
```
