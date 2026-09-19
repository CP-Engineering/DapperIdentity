# DapperIdentity
Microsoft Identity Framework with Custom User/Role Stores using Identity

This is geared toward using Identity Framework for Blazor Server applications where you are using Dapper for data access.
The UserStore and RoleStore data access layer classes have been customized to use Dapper. They are in no-way complete. All of the underlying Identity Logic is unchanged, only they way Identity accesses the data in a database.

The `UserStore` and `RoleStore` classes use the Generic Repository here:
https://github.com/gismofx/DapperRepository and also on NuGet: https://www.nuget.org/packages/TheDapperRepository/.

## Pull Requests Welcomed!

More Examples coming soon.

## Getting Started

### JWT Auth Tokens
In your API project Add the entries to secrets.json/AppSettings.json whatever app secrests store you use:
```json
  "JwtTokenSettings": {
    "ValidIssuer": "ExampleIssuer",
    "ValidAudience": "ValidAudience",
    "SymmetricSecurityKey": "my_super_secret_key",
    "JwtExpireSeconds": 900,
    "RefreshTokenLifeDays": 4
  }
```

#### Password-reset and registration links

The API emails users a link to set or reset their password. Two settings control it.

**`DapperIdentity:AppBaseUrl` — required.** The public address of the app that hosts the
password-reset page, used to build that link. Note that this is the address of your *front end*
(for example your Blazor app), not of the API, even though it is set in the API's configuration.
It differs per environment, so it belongs in `appsettings.{Environment}.json` or wherever your
environment-specific settings live:

```json
  "DapperIdentity": {
    "AppBaseUrl": "https://app.example.com"
  }
```

The API **will not start** without it, and says so by name. There is deliberately no fallback:
the only one available would be the incoming request, and deriving the link from a request
header lets anyone who can call the forgot-password endpoint choose where a real reset token is
sent.

**`DapperIdentity:PasswordLinkLifetime` — optional, default 24 hours.** How long a link stays
valid, as `hours:minutes:seconds`. It must be between **15 minutes and 24 hours**; anything else
stops the API starting. It is a policy rather than a per-environment value, so set it once in
`appsettings.json` if you set it at all:

```json
  "DapperIdentity": {
    "PasswordLinkLifetime": "01:00:00"
  }
```

You can also set it in code, the standard ASP.NET Core way. A `Configure` call made *after*
`AddJwtIdentity` takes precedence over both the default and the configuration key:

```c#
  builder.Services.AddJwtIdentity(builder.Configuration);
  builder.Services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromMinutes(30));
```

The same 15-minute-to-24-hour range applies however the value is set, and the emails always quote
the lifetime actually being enforced.

> **A persisted Data Protection key ring is required for this lifetime to hold.** The token in the
> link is sealed with a Data Protection key rather than stored. If the key ring is ephemeral — on
> IIS, an app pool that does not load its user profile — every outstanding link dies at the next
> app-pool recycle, whatever lifetime is configured. On IIS the fix is to set the app pool's
> **Load User Profile** to `True`.

In `program.cs` Add the following:
```c#
  builder.Services.AddIAppSettings(new MyAppSettings()); //Create a class that implements IAppSettings
  builder.Services.AddDbConnectionInstantiatorForRepositories<MySqlConnection>(conStrBuilder.GetConnectionString(true)); //eg
  builder.Services.AddJwtIdentity(builder.Configuration);

  builder.Services.AddTransient<IAuthEmailSender, EmailSender>(); //Create a class that implements IAuthEmailSender

```

In your controller decorate your endpoints with `[Authorize]` per MS docs
```c#
    [Authorize]
    [HttpGet("{id:guid}")]
    public async Task<ActionResult<Client>> Get(string id)
    {
        return Ok(await ClientRepository.FindByIDAsync(id));
    }


    [Authorize(Roles = "Admin,UsersEdit")]
    [HttpGet("getuser\{userId}")]
    public async Task<ActionResult<ApplicationUser>> Get(string userId)
    {
        var user = (await GetUsersWithRoles(userId:userId)).First();
        return Ok(user);
    }

```

On the client-side(if you're using C#/Blazor):
```c#
@inject JWTWasmClient AuthClient

@code {
 private async Task LoginClick()
 {
     var response = await AuthClient.Login(new() { Email = userName, Password = password }, ((AuthStateProvider)authStateProvider).NotifyUserAuthentication);
 
     if (!string.IsNullOrWhiteSpace(response.Token))
     {
         navManager.NavigateTo(@"\");
         await AppState.LoadCurrentUser(true);
     }
     else
     {
         Snackbar.Add(new MarkupString("There was an error logging in. Bad login info or internet may be disconnected. Try again later"), Severity.Error);
     }
 }
}
```



##


### Blazor Server with Cookie Auth
In `startup.cs` add the following
```c#
using DapperIdentity.Services;
using DapperRepository;
```

In `ConfigureServices` method, add the following:
```c#
var connString = Configuration.GetConnectionString("DefaultConnection");
services.AddDbConnectionInstantiatorForRepositories<MySqlConnection>(connString);

//To use DEFAULT MS Identity UI Razor Pages Add Vanilla
//services.AddDapperIdentityWithVanillaUIAndDefaults();
//or only Identity Middle and Back-End use this:
services.AddDapperIdentityWithCustomCookies(TimeSpan.FromMinutes(10));//Or however long you want login cookie to last

 
services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<DapperIdentity.Models.CustomIdentityUser>>();
```

## Note on using Microsoft's Default Identity UI
*Note: In order to scaffold, it requires a DBContext class; create one; it is not used and can be delete after scaffolding.*  
You **Must** Scaffold out the pages that you want to use and **add** the following to the top of each page's cshtml.cs file:  
```c#
using IdentityUser = DapperIdentity.Models.CustomIdentityUser
```

Also to top of `_Login_Partial.cshtml` add:  
```c#
@using IdentityUser = DapperIdentity.Models.CustomIdentityUser
```

## Alternative Start To Microsoft's Default UI
Logging in requires an HTTP POST so the cookies can created.
Here's a simple HTML form section which you can use for logging in which you can put on any page in Blazor:

```html
    <form action="Identity/Login" method="post"><!--cookie-->
        <input name="name" type="text" />
        <input name="password" type="password" />
        <input type="submit" />
    </form> 
```



To Do:
* Make a better/generic login razor component. 
* Handle invalid user/pass. 
* Add remember me checkbox
* Handle Email Confirmation(Add Controller Action)
* NuGet Package
