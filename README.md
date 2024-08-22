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
            // TODO: Use clientId to get the shared secret from 
			// Azure Key Vault, IdentityServer4, or a database
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
    var widget = client.Get<Widget>(requestUri).Result;
    // do something with widget ID 1...
}
```

## Versioning

Version 6.0.0 targets.NET Core 8.0

## Authors

[James Still](http://www.squarewidget.com)

## License

This project is licensed under the MIT License.

## Acknowledgments

* [Joonas Westlin](https://joonasw.net/view/creating-auth-scheme-in-aspnet-core-2)