using CPE.DapperIdentity.Abstractions;
using CPE.DapperIdentity.Stores.Models;
using CPE.DapperIdentity.Jwt.Server.Controllers;
using CPE.DapperIdentity.Stores;
using DapperRepository;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Data;
using System.Reflection;
using System.Security.Claims;
using IdentityRole = CPE.DapperIdentity.Stores.Models.CustomIdentityRole;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;
// This class sits in Microsoft.Extensions.DependencyInjection so AddJwtIdentity is discoverable
// from a consumer's Program.cs with no using at all, so the library's own types need importing.
using CPE.DapperIdentity.Jwt.Server;

namespace Microsoft.Extensions.DependencyInjection;
/// <summary>
/// Registration entry points for the JWT server package.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers everything needed to serve JWT authentication: the Dapper stores, the token
    /// service, <c>JwtAuthController</c>, ASP.NET Core Identity, and JWT bearer authentication.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only <c>JwtAuthController</c> is routed - see <c>SelectedControllerFeatureProvider</c>.
    /// </para>
    /// <para>
    /// The Identity options set here are permissive by design for an API: no confirmed account
    /// required, and a six-character password with no digit, symbol or uppercase requirement.
    /// A consumer that wants stricter rules must reconfigure <c>IdentityOptions</c> afterwards.
    /// </para>
    /// <para>
    /// Bearer validation is strict - issuer, audience, lifetime and signing key are all checked,
    /// with <c>ClockSkew</c> at zero, so a token is rejected the second it expires rather than
    /// five minutes later.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configuration">
    /// Must contain a <c>JwtTokenSettings</c> section with <c>ValidIssuer</c>,
    /// <c>ValidAudience</c> and <c>SymmetricSecurityKey</c>, and a top-level
    /// <c>DapperIdentity:AppBaseUrl</c> giving the application's own public address.
    /// </param>
    /// <returns>The same collection, for chaining.</returns>
    /// <exception cref="InvalidOperationException">
    /// <c>DapperIdentity:AppBaseUrl</c> is absent, or is not an absolute http/https URL.
    /// </exception>
    public static IServiceCollection AddJwtIdentity(this IServiceCollection services,
                                                    IConfiguration configuration)
    {
        // Validated here rather than where it is used, so a deployment that forgot the setting
        // fails at startup instead of discovering it when a user cannot reset their password.
        services.AddSingleton(ReadAppBaseUrl(configuration));
        services.AddSingleton(new PasswordResetRateLimiter());

        services.TryAddDapperIdentityDatabaseStores();
        services.AddScoped<TokenService>();
        // Route JwtAuthController and nothing else from this assembly. Adding the AssemblyPart on
        // its own would hand the consumer every controller this library happens to contain, now
        // and in future - see SelectedControllerFeatureProvider for why the narrowing has to be a
        // removal and why it is scoped to this assembly.
        var assembly = typeof(JwtAuthController).GetTypeInfo().Assembly;
        var builder = services.AddControllers();
        builder.PartManager.ApplicationParts.Add(new AssemblyPart(assembly));
        builder.PartManager.FeatureProviders.Add(
            new SelectedControllerFeatureProvider(typeof(JwtAuthController)));



        services.AddIdentity<IdentityUser, IdentityRole>(
         options =>
         {
             options.SignIn.RequireConfirmedAccount = false;
             options.User.RequireUniqueEmail = true;
             options.Password.RequireDigit = false;
             options.Password.RequiredLength = 6;
             options.Password.RequireNonAlphanumeric = false;
             options.Password.RequireUppercase = false;
         })
        .AddSignInManager<CustomSignInManager>()
        .AddRoleStore<RoleStore>()
        .AddUserStore<UserStore>()
        .AddDefaultTokenProviders(); 
        

        //Microsoft.AspNetCore.Authentication.JwtBearer.


        services.AddAuthentication(options => {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // Microsoft.AspNetCore.Authentication.AuthenticationSchemeBuilder( .Jw JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.IncludeErrorDetails = true;
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ClockSkew = TimeSpan.Zero,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = configuration.GetSection("JwtTokenSettings")["ValidIssuer"],
                ValidAudience = configuration.GetSection("JwtTokenSettings")["ValidAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    System.Text.Encoding.UTF8.GetBytes(configuration.GetSection("JwtTokenSettings")["SymmetricSecurityKey"]!)
                ),
                RoleClaimType = ClaimTypes.Role,
                
            };
        });


        return services;
    }

    /// <summary>
    /// Reads and validates the application's public base address from configuration.
    /// </summary>
    /// <remarks>
    /// Required, with no fallback on purpose. The obvious fallback would be the incoming request,
    /// which is exactly what this setting exists to stop the library trusting - so a deployment
    /// that has not set it must fail loudly rather than quietly go back to the unsafe behaviour.
    /// </remarks>
    /// <param name="configuration">The application's configuration.</param>
    /// <returns>The validated base address.</returns>
    /// <exception cref="InvalidOperationException">The setting is missing or unusable.</exception>
    private static AppBaseUrl ReadAppBaseUrl(IConfiguration configuration)
    {
        const string key = "DapperIdentity:AppBaseUrl";
        var configured = configuration[key];

        if (string.IsNullOrWhiteSpace(configured))
        {
            throw new InvalidOperationException(
                $"Configuration is missing '{key}'. Set it to this application's own public " +
                "address, for example \"https://app.example.com\". It is used to build the " +
                "password-reset link that is emailed to users, and has no safe default.");
        }

        if (!Uri.TryCreate(configured, UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            throw new InvalidOperationException(
                $"Configuration value '{key}' is '{configured}', which is not an absolute http " +
                "or https URL. A relative value produces an unusable link in an email.");
        }

        return new AppBaseUrl(parsed);
    }

    /// <summary>
    /// Registers the consumer's <see cref="IAppSettings"/> as a singleton.
    /// </summary>
    /// <remarks>
    /// Required by <c>JwtAuthController</c>, which reads <c>ApplicationName</c> into the
    /// registration and password-reset emails. Without this the controller cannot be constructed.
    /// </remarks>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="appSettings">The consumer's own instance, registered as supplied.</param>
    /// <returns>The same collection, for chaining.</returns>
    public static IServiceCollection AddIAppSettings(this IServiceCollection services, IAppSettings appSettings)
    {
        services.AddSingleton<IAppSettings>(appSettings);
        return services;
    }


}