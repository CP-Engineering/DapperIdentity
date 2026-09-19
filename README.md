# CPE.DapperIdentity

ASP.NET Core Identity with the user and role stores backed by **Dapper** instead of Entity
Framework. Identity's own logic is unchanged; only the way it reads and writes the database is.

The stores use the generic repository from
[TheDapperRepository](https://www.nuget.org/packages/TheDapperRepository/).

## Packages

Five packages, one per dependency profile, always released together at the same version.
Install only the ones your project needs; each pulls in what it depends on.

| Package | Use it in | Brings in |
|---|---|---|
| `CPE.DapperIdentity.Jwt.Server` | An ASP.NET Core API issuing JWTs | Stores, Abstractions, JwtBearer |
| `CPE.DapperIdentity.Jwt.Client` | A Blazor WebAssembly app calling that API | Abstractions, Blazored.LocalStorage |
| `CPE.DapperIdentity.Cookies.Server` | A Blazor Server / MVC app on cookie auth | Stores, Abstractions |
| `CPE.DapperIdentity.Stores` | Anything that only needs the Dapper stores | Abstractions, Dapper |
| `CPE.DapperIdentity.Abstractions` | Shared contracts and wire models | nothing |

All five target `net8.0` and `net10.0`. Namespaces match the package ids
(`CPE.DapperIdentity.Stores`, `CPE.DapperIdentity.Jwt.Client`, ...). The `Add...` registration
methods live in `Microsoft.Extensions.DependencyInjection`, so `Program.cs` needs no extra using.

## Database

The tables the stores expect are defined in two scripts shipped inside
`CPE.DapperIdentity.Stores`, under `sql/` in the package: `mysql.txt` (MySQL / MariaDB) and
`Sqlite.txt`. Run the one for your database before first use.

The stores open connections through TheDapperRepository, so register a connection factory first:

```c#
using DapperRepository;

builder.Services.AddDbConnectionInstantiatorForRepositories<MySqlConnection>(connectionString);
```

## JWT: the API (`CPE.DapperIdentity.Jwt.Server`)

### Configuration

```json
  "JwtTokenSettings": {
    "ValidIssuer": "ExampleIssuer",
    "ValidAudience": "ExampleAudience",
    "SymmetricSecurityKey": "keep-this-in-a-secret-store-not-in-appsettings",
    "JwtExpireSeconds": 900,
    "RefreshTokenLifeDays": 4
  }
```

### `Program.cs`

```c#
builder.Services.AddDbConnectionInstantiatorForRepositories<MySqlConnection>(connectionString);
builder.Services.AddIAppSettings(new MyAppSettings());            // implements IAppSettings
builder.Services.AddTransient<IAuthEmailSender, MyEmailSender>(); // implements IAuthEmailSender
builder.Services.AddJwtIdentity(builder.Configuration);
```

`AddJwtIdentity` registers the stores, the token service, ASP.NET Core Identity, JWT bearer
authentication, and `JwtAuthController` at `/api/jwtauth` with `login`, `refresh`, `register`,
`ForgotPassword` and `ResetPassword`. It routes that one controller only.

`IAppSettings.ApplicationName` is the name used in account emails. `IAuthEmailSender` is how
those emails are sent; the library never talks to an SMTP server itself.

Protect your own endpoints with `[Authorize]` / `[Authorize(Roles = "...")]` as usual.

### Password-reset and registration links

The API emails users a link to set or reset their password. Two settings control it.

**`DapperIdentity:AppBaseUrl` is required.** The public address of the app that hosts the
password-reset page, used to build that link. This is the address of your *front end* (for
example your Blazor app), not of the API, even though it is set in the API's configuration. It
differs per environment, so it belongs in `appsettings.{Environment}.json` or wherever your
environment-specific settings live:

```json
  "DapperIdentity": {
    "AppBaseUrl": "https://app.example.com"
  }
```

The API **will not start** without it, and says so by name. There is deliberately no fallback:
the only one available would be the incoming request, and deriving the link from a request header
lets anyone who can call the forgot-password endpoint choose where a real reset token is sent.

**`DapperIdentity:PasswordLinkLifetime` is optional, default 24 hours.** How long a link stays
valid, as `hours:minutes:seconds`, between **15 minutes and 24 hours**; anything else stops the
API starting. It is a policy rather than a per-environment value, so set it once in
`appsettings.json` if you set it at all:

```json
  "DapperIdentity": {
    "PasswordLinkLifetime": "01:00:00"
  }
```

It can also be set in code. A `Configure` call made *after* `AddJwtIdentity` takes precedence
over both the default and the configuration key, and the same range applies:

```c#
builder.Services.AddJwtIdentity(builder.Configuration);
builder.Services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromMinutes(30));
```

The emails always quote the lifetime actually being enforced.

> **A persisted Data Protection key ring is required for this lifetime to hold.** The token in the
> link is sealed with a Data Protection key rather than stored. If the key ring is ephemeral (on
> IIS, an app pool that does not load its user profile) every outstanding link dies at the next
> app-pool recycle, whatever lifetime is configured. On IIS, set the app pool's
> **Load User Profile** to `True`.

## JWT: the Blazor WebAssembly client (`CPE.DapperIdentity.Jwt.Client`)

### Configuration (`wwwroot/appsettings.json`)

```json
  "AuthServer": {
    "Endpoint": "https://api.example.com"
  }
```

### `Program.cs`

```c#
builder.Services.AddJwtWasmClient();
```

This registers `JwtWasmClient` (login, logout, token refresh, forgot and reset password, with the
tokens kept in browser local storage), the lower-level `JwtAuthClient` it wraps, and
`HttpInterceptorService`, which puts a valid bearer token on every outgoing `HttpClient` request
and refreshes it shortly before it expires. Call `RegisterEvent()` on the interceptor once at
startup and `DisposeEvent()` when you are done with it.

The library does not ship an `AuthenticationStateProvider`; your app keeps its own and passes its
notify callback in:

```c#
@inject JwtWasmClient AuthClient

private async Task LoginClick()
{
    var result = await AuthClient.Login(new AuthRequest { Email = email, Password = password },
                                        myAuthStateProvider.NotifyUserAuthentication);
    if (result.Succeeded)
    {
        navManager.NavigateTo("/");
        return;
    }

    message = result.Failure switch
    {
        AuthFailure.InvalidCredentials => "That email and password don't match.",
        AuthFailure.ServerError        => "The server had a problem. Try again shortly.",
        _                              => "Login failed.",
    };
}
```

`AuthResult` is either tokens or a reason there are none; `Succeeded` tells you which. Network
failures are not converted into a result and surface as exceptions, so wrap the call if the app can
be offline.

## Cookies: Blazor Server and MVC (`CPE.DapperIdentity.Cookies.Server`)

```c#
builder.Services.AddDbConnectionInstantiatorForRepositories<MySqlConnection>(connectionString);
builder.Services.AddDapperIdentityWithCustomCookies(TimeSpan.FromMinutes(30));
```

`AddDapperIdentityWithCustomCookies` registers the stores, ASP.NET Core Identity and cookie
authentication, with the cookie lifetime you pass (sliding by default). No UI is included.
**Sign-in requires a confirmed email by default**; pass `requireConfirmedEmail: false` if your app
does not send confirmation mail.

To use Microsoft's Identity UI pages instead, call `AddDapperIdentityWithVanillaUIAndDefaults` and
scaffold the pages you need. This package does not reference `Microsoft.AspNetCore.Identity.UI` or
call `AddDefaultUI()`, so the pages are the ones you scaffold. Scaffolding asks for a `DbContext`;
create an empty one, and delete it afterwards. Then alias the user type at the top of each scaffolded page's `.cshtml.cs` and of
`_LoginPartial.cshtml`:

```c#
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;
```

`AddIdentityControllers` adds a small `IdentityController` at `/Identity/{action}` for form-post
login, logout and email confirmation without the default UI. Signing in has to be an HTTP POST
so the cookie can be set:

```html
<form action="Identity/Login" method="post">
    <input name="name" type="text" />
    <input name="password" type="password" />
    <input type="submit" />
</form>
```

## Versioning

Every package in this repo carries the same version, set once in `Directory.Build.props`. The
0.x line means the API can still change between minor versions; read the release notes before
upgrading.

## License

MIT.
