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
    /// <c>ValidAudience</c> and <c>SymmetricSecurityKey</c>.
    /// </param>
    /// <returns>The same collection, for chaining.</returns>
    public static IServiceCollection AddJwtIdentity(this IServiceCollection services,
                                                    IConfiguration configuration)
    {
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