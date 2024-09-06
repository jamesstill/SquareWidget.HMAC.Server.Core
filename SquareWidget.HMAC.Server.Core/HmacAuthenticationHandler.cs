using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace SquareWidget.HMAC.Server.Core
{
    public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
    {
        private readonly SharedSecretStoreService _sharedSecretStoreService;

        public HmacAuthenticationHandler(
            IOptionsMonitor<HmacAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            SharedSecretStoreService sharedSecretStoreService)
            : base(options, logger, encoder)
        {
            _sharedSecretStoreService = sharedSecretStoreService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // request header must contain Hash and TimeStamp
            if (!Request.Headers.TryGetValue(Options.HashHeaderName, out StringValues hashHeaderValue))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Missing authorization header for clientId and hash value"));
            }

            if (!Request.Headers.TryGetValue(Options.TimestampHeaderName, out StringValues timestampValue))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Missing timestamp header value."));
            }

            var parts = hashHeaderValue.ToString().Split(':');
            if (parts.Length != 2)
            {
                return await Task.Run(() => AuthenticateResult.Fail("Hash header must be in the form {clientId:clientHash}"));
            }

            var clientId = parts[0];
            var clientHash = parts[1];
            var sharedSecret = await _sharedSecretStoreService.GetSharedSecretAsync(clientId);

            if (!IsValidTimestamp(timestampValue, out DateTimeOffset timestamp))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Timestamp is not a valid Unix timestamp value."));
            }
            if (!PassesThresholdCheck(timestamp))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Authentication request did not pass the timestamp threshold check."));
            }
            if (!ComputeHash(sharedSecret, timestamp, clientHash))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Client authentication failed."));
            }

            var claims = new[] { new Claim(ClaimTypes.Name, clientId) };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return await Task.Run(() => AuthenticateResult.Success(ticket));
        }

        /// <summary>
        /// Parse a string representing a Unix timestamp (e.g., 16609335560)
        /// </summary>
        /// <param name="timestampValue">Unix Timestamp</param>
        /// <param name="offset">DateTimeOffset</param>
        /// <returns></returns>
        private static bool IsValidTimestamp(string timestampValue, out DateTimeOffset offset)
        {
            offset = DateTimeOffset.UtcNow;
            try
            {
                long value = long.Parse(timestampValue);
                offset = DateTimeOffset.FromUnixTimeSeconds(value);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Returns true if client timestamp is within the delay value
        /// </summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        private bool PassesThresholdCheck(DateTimeOffset offset)
        {
            var ts = DateTimeOffset.UtcNow.Subtract(offset);
            return ts.TotalSeconds <= Options.ReplayAttackDelayInSeconds;
        }

        /// <summary>
        /// Returns true if the server can generate the same hash as the one the client provided.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="offset">Unix Timestamp</param>
        /// <param name="clientHash"></param>
        /// <returns></returns>
        private static bool ComputeHash(string sharedSecret, DateTimeOffset offset, string clientHash)
        {
            string hashString;
            var ticks = offset.ToUnixTimeSeconds().ToString();
            var key = Encoding.UTF8.GetBytes(sharedSecret);
            using (var hmac = new HMACSHA256(key))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(ticks));
                hashString = Convert.ToBase64String(hash);
            }
            return hashString.Equals(clientHash, StringComparison.Ordinal);
        }
    }
}
