using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace SquareWidget.HMAC.Server.Core
{
    public static class HmacAuthenticationExtensions
    {
        public static AuthenticationBuilder AddHmacAuthentication<T>(this AuthenticationBuilder builder)
            where T : SharedSecretStoreService
        {
            return AddHmacAuthentication<T>(builder, HmacAuthenticationDefaults.AuthenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddHmacAuthentication<T>(this AuthenticationBuilder builder, string authenticationScheme)
            where T : SharedSecretStoreService
        {
            return AddHmacAuthentication<T>(builder, authenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddHmacAuthentication<T>(this AuthenticationBuilder builder, Action<HmacAuthenticationOptions> configureOptions)
            where T : SharedSecretStoreService
        {
            return AddHmacAuthentication<T>(builder, HmacAuthenticationDefaults.AuthenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddHmacAuthentication<T>(this AuthenticationBuilder builder, string authenticationScheme, Action<HmacAuthenticationOptions> configureOptions)
            where T : SharedSecretStoreService
        {
            builder.Services.AddTransient<SharedSecretStoreService, T>();
            return builder.AddScheme<HmacAuthenticationOptions, HmacAuthenticationHandler>(authenticationScheme, configureOptions);
        }
    }
}
