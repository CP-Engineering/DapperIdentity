using CPE.DapperIdentity.Cookies.Server;
using CPE.DapperIdentity.Cookies.Server.Controllers;
using CPE.DapperIdentity.Stores;
using DapperRepository;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.DependencyInjection;
using System.Data;
using System.Reflection;
using IdentityRole = CPE.DapperIdentity.Stores.Models.CustomIdentityRole;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration entry points for the cookie-authentication server package.
/// </summary>
/// <remarks>
/// Sits in <c>Microsoft.Extensions.DependencyInjection</c> so these are reachable from a
/// consumer's <c>Program.cs</c> without a using directive.
/// </remarks>
public static class DapperIdentityCookieServiceCollectionExtensions
{

    /// <summary>
    /// Added because docs say so, but this is NOT required. Maybe because some magic in blazor project? or Net 5?
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddIdentityControllers(this IServiceCollection services)
    {
        // Routes IdentityController and nothing else from this assembly. Until 2026-09-16 this
        // method called AddApplicationPart alone, which routes EVERY controller here into the
        // consumer - which is how an unfinished BasicAuthController.Login became a live
        // [AllowAnonymous] endpoint in a production app. The allow-list is the fix; see
        // SelectedControllerFeatureProvider.
        var assembly = typeof(IdentityController).GetTypeInfo().Assembly;
        services.AddMvcCore()
                .AddControllersAsServices()
                .AddApplicationPart(assembly)
                .ConfigureApplicationPartManager(apm =>
                    apm.FeatureProviders.Add(
                        new SelectedControllerFeatureProvider(typeof(IdentityController))));
        return services;
    }


    // AddBasicAuthController removed 2026-09-16 along with the Basic and Digest auth experiments.
    // It never registered a controller - it only called TryAddDapperIdentityDatabaseStores() - so
    // its name promised something it did not do, and the controller it named was unfinished
    // scaffolding routed into consumers by AddIdentityControllers rather than by this method.
    // The last commit containing that work is tagged learning/basic-digest-auth.

    /// <summary>
    /// Add Dapper Identity - No UI
    /// </summary>
    /// <typeparam name="T">Your dapper compatible IDbConnection of your database</typeparam>
    /// <param name="services"></param>
    /// <param name="connectionString">database connection string</param>
    /// <param name="cookieExpiration"></param>
    /// <param name="requireConfirmedEmail"></param>
    /// <param name="slidingExpiration"></param>
    /// <returns></returns>
    public static IServiceCollection AddDapperIdentityWithCustomCookies<T>(this IServiceCollection services,
                                                                     string connectionString,
                                                                     TimeSpan cookieExpiration,
                                                                     bool requireConfirmedEmail = true,
                                                                     bool slidingExpiration = true) where T : IDbConnection
    {
        //services.AddDbConnectionInstantiatorForRepositories<T>(connectionString);
        return services.AddDapperIdentityWithCustomCookies(cookieExpiration, requireConfirmedEmail, slidingExpiration);
    }

    /// <summary>
    /// Use this method to setup Identity
    /// Assumes you have already added the dbinstantiator
    /// </summary>
    /// <param name="services"></param>
    /// <param name="cookieExpiration">e.g. TimeSpan.FromDays(7) or TimeSpan.FromMinutes(30);</param>
    /// <param name="requireConfirmedEmail"></param>
    /// <param name="slidingExpiration"></param>
    /// <returns></returns>
    public static IServiceCollection AddDapperIdentityWithCustomCookies(this IServiceCollection services,
                                                                     TimeSpan cookieExpiration,
                                                                     bool requireConfirmedEmail = true,
                                                                     bool slidingExpiration = true)
    {

        services.TryAddDapperIdentityDatabaseStores();
        services.AddIdentity<IdentityUser, IdentityRole>()
            .AddDefaultTokenProviders()
            .AddSignInManager<CustomSignInManager>()
            .AddRoleStore<RoleStore>()
            .AddUserStore<UserStore>(); //maybe deleet?
        services.Configure<IdentityOptions>(opts =>
        {
            opts.SignIn.RequireConfirmedEmail = requireConfirmedEmail;
            opts.User.RequireUniqueEmail = true;
        }
        );

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(o => o.LoginPath = new PathString("/Identity/Account/Login"));

        services.Configure<SecurityStampValidatorOptions>(o =>
            o.ValidationInterval = TimeSpan.FromMinutes(1));

        //timespan
        services.ConfigureApplicationCookie(o =>
        {
            o.ExpireTimeSpan = cookieExpiration;
            o.SlidingExpiration = slidingExpiration;
        }
        );

        return services;
    }

    /// <summary>
    /// Adds vanilla Identity. Assumes you have scaffolded or are using Identity UI/Razor Pages Area
    /// </summary>
    /// <typeparam name="T">The ADO.NET connection type the repositories should open.</typeparam>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="connectionString">Connection string the repositories open <typeparamref name="T"/> with.</param>
    /// <param name="requireConfirmedEmail">Whether sign-in requires a confirmed email address.</param>
    /// <param name="slidingExpiration">Whether the auth cookie's lifetime renews on activity.</param>
    /// <returns>The same collection, for chaining.</returns>
    /// <remarks>The cookie lifetime is fixed at seven days by this overload.</remarks>
    public static IServiceCollection AddDapperIdentityWithVanillaUIAndDefaults<T>(this IServiceCollection services,
                                                            string connectionString,
                                                            bool requireConfirmedEmail = true,
                                                            bool slidingExpiration = true) where T : IDbConnection
    {
        services.AddDbConnectionInstantiatorForRepositories<T>(connectionString);
        return services.AddDapperIdentityWithVanillaUIAndDefaults(TimeSpan.FromDays(7), requireConfirmedEmail, slidingExpiration);
    }

    /// <summary>
    /// Adds Dapper Identity Stores with DEFAULT Microsoft Identity UI
    /// </summary>
    /// <param name="services"></param>
    /// <param name="cookieExpiration"></param>
    /// <param name="requireConfirmedEmail"></param>
    /// <param name="slidingExpiration"></param>
    /// <returns></returns>
    public static IServiceCollection AddDapperIdentityWithVanillaUIAndDefaults(this IServiceCollection services,
                                                            TimeSpan cookieExpiration,
                                                            bool requireConfirmedEmail = true,
                                                            bool slidingExpiration = true)
    {
        services.TryAddDapperIdentityDatabaseStores();

        services.AddIdentity<IdentityUser, IdentityRole>()
            //.AddDefaultUI()
            .AddDefaultTokenProviders();

        services.Configure<IdentityOptions>(opts =>
        {
            opts.SignIn.RequireConfirmedEmail = requireConfirmedEmail;
            opts.User.RequireUniqueEmail = true;
        }
        );

        services.Configure<SecurityStampValidatorOptions>(o =>
            o.ValidationInterval = TimeSpan.FromMinutes(1));

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(o => o.LoginPath = new PathString("/Identity/Account/Login"));

        //timespan
        services.ConfigureApplicationCookie(o =>
        {
            o.ExpireTimeSpan = cookieExpiration; //TimeSpan.FromDays(7);//FromMinutes(30);
            o.SlidingExpiration = slidingExpiration;
        }
        );

        return services;

    }

}