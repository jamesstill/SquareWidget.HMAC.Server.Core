# SquareWidget.HMAC.Server.Core

Middleware HMAC-based authentication service for .NET Core 8.0

### Status

[![Build status](https://jamesstill.visualstudio.com/SquareWidget.HMAC.Server.Core/_apis/build/status/SquareWidget.HMAC.Server.Core)](https://jamesstill.visualstudio.com/SquareWidget.HMAC.Server.Core/_build/latest?definitionId=13)

### Prerequisites

.NET Core 8.0

### Getting Started

See the [documentation](https://squarewidget.com/squarewidget-hmac-middleware) for usage. Download the NuGet package in your API. Implement a shared secret store service from abstract base class SharedSecretStoreService as in this example:

```
using SquareWidget.HMAC.Server.Core;
using System.Threading.Tasks;

namespace SquareWidget.ExampleApi
{
    public class MySharedSecretStoreService : SharedSecretStoreService
    {
        public override Task<string> GetSharedSecretAsync(string clientId)
        {
            // NOT FOR PRODUCTION: Hard-coded password returned; see Key Vault example below
            return Task.Run(() => "P@ssw0rd");
        }
    }
}
```

Add to ConfigureServices method in Startup.cs to register the authentication handler:

```
services
    .AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme)
    .AddHmacAuthentication<MySharedSecretStoreService>(o => { });
```

### Azure Key Vault

Suppose you wanted to implement a `SharedSecretStoreService` that fetched a secret value
from Key Vault for the clientId. In `appsettings.json` provide the path to Key Vault:

```
"AzureKeyVaultSettings": {
  "Uri": "https://your-path.vault.azure.net/"
}
```

Reference the Azure SDK for .NET to get the `Azure.Security.KeyVault.Secrets` library. 
Then implement the store service. Here is an example with IConfiguration dependency injection 
and a simple retry policy for resiliency.

```
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace SquareWidget.ExampleApi
{
    public class KeyVaultService(IConfiguration configuration) : SharedSecretStoreService
    {
        protected readonly IConfiguration _configuration = configuration;

        public override Task<string> GetSharedSecretAsync(string clientId)
        {
            var options = new SecretClientOptions()
            {
                Retry =
                {
                    Delay = TimeSpan.FromSeconds(2),
                    MaxDelay = TimeSpan.FromSeconds(5),
                    MaxRetries = 3,
                    Mode = Azure.Core.RetryMode.Exponential
                }
            };

            var uri = new Uri(_configuration["AzureKeyVaultSettings:Uri"]);

            var client = new SecretClient(uri, new DefaultAzureCredential(), options);
            var secret = await client.GetSecretAsync(clientId);
            return secret.Value.Value;
        }
    }
}
```

### Options

By default the authentication handler looks for two request headers called "Hash" and "Timestamp" but 
these can be overridden if the client passes in another value in the request header:

```
services
    .AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme)
    .AddHmacAuthentication<MySharedSecretStoreService>(o => 
    {
        o.HashHeaderName = "MyHash";
        o.TimestampHeaderName = "MyTimestamp";
    });
```

There is a replay attack value of 15 seconds. This can be overridden which is especially useful when debugging code:

```
services
    .AddAuthentication(HmacAuthenticationDefaults.AuthenticationScheme)
    .AddHmacAuthentication<MySharedSecretStoreService>(o => 
    {
        o.ReplayAttackDelayInSeconds = 900; // 15 mins
    });
```

### Client Side

Use SquareWidget.HMAC.Client.Core package. See the [documentation](https://squarewidget.com/squarewidget-hmac-middleware). 
Bring in the package and use HmacHttpClient:

```
var baseUri = "https://localhost:12345";
var credentials = new ClientCredentials
{
    ClientId = "testClient",
    ClientSecret = "testSecret"
};

var requestUri = "api/widgets/1";
using (var client = new HmacHttpClient(baseUri, credentials))
{
    var options = new JsonSerializerOptions();
    var response = await client.GetAsync(requestUri);
    var content = await response.Content.ReadAsStringAsync();
    var widget = JsonSerializer.Deserialize<Widget>(content, options);

    // do something with widget ID 1...
}
```

## Versioning

Version 8.1.0 targets.NET Core 8.0

## Authors

[James Still](http://www.squarewidget.com)

## License

This project is licensed under the MIT License.

## Acknowledgments

* [Joonas Westlin](https://joonasw.net/view/creating-auth-scheme-in-aspnet-core-2)