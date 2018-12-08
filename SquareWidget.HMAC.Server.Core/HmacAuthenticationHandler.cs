using System;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SquareWidget.HMAC.Server.Core
{
    public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
    {
        private readonly SharedSecretStoreService _sharedSecretStoreService;

        public HmacAuthenticationHandler(
            IOptionsMonitor<HmacAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            SharedSecretStoreService sharedSecretStoreService)
            : base(options, logger, encoder, clock)
        {
            _sharedSecretStoreService = sharedSecretStoreService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // request header must contain Hash and TimeStamp
            if (!Request.Headers.ContainsKey(Options.HashHeaderName))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Missing authorization header for clientId and hash value"));
            }

            if (!Request.Headers.ContainsKey(Options.TimestampHeaderName))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Missing timestamp header value."));
            }

            var hashHeaderValue = Request.Headers[Options.HashHeaderName].ToString();
            var parts = hashHeaderValue.Split(':');
            if (parts.Length != 2)
            {
                return await Task.Run(() => AuthenticateResult.Fail("Hash header must be in the form {clientId:clientHash}"));
            }

            var clientId = parts[0];
            var clientHash = parts[1];
            var timestampValue = Request.Headers[Options.TimestampHeaderName].ToString();
            var sharedSecret = await _sharedSecretStoreService.GetSharedSecretAsync(clientId);

            if (!IsValidTimestamp(timestampValue, out DateTime timestamp))
            {
                return await Task.Run(() => AuthenticateResult.Fail("Timestamp is not ISO 8601 format yyyy-MM-ddTHH:mm:ss.fffffffZ."));
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
        /// Return ClientId part of {ClientId:Hash} passed into request header by client
        /// </summary>
        /// <param name="clientIdAndHash"></param>
        /// <returns></returns>
        private string GetClientId(string clientIdAndHash)
        {
            return clientIdAndHash.Substring(0, clientIdAndHash.IndexOf(':'));
        }

        /// <summary>
        /// Return Hash part of {clientId:Hash} passed into request header by client
        /// </summary>
        /// <param name="clientIdAndHash"></param>
        /// <returns></returns>
        private string GetClientHash(string clientIdAndHash)
        {
            return clientIdAndHash.Substring(clientIdAndHash.IndexOf(':') + 1);
        }

        /// <summary>
        /// Parse a string representing a UTC timestamp of style "o" E.g.: "2013-01-12T16:11:20.0904778Z"
        /// </summary>
        /// <param name="timestampValue">UTC in style "o"</param>
        /// <param name="timestamp">DateTime</param>
        /// <returns></returns>
        private static bool IsValidTimestamp(string timestampValue, out DateTime timestamp)
        {
            return DateTime.TryParseExact(timestampValue, "o", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out timestamp);
        }

        /// <summary>
        /// Returns true if client timestamp is within the delay value
        /// </summary>
        /// <param name="timestamp"></param>
        /// <returns></returns>
        private bool PassesThresholdCheck(DateTime timestamp)
        {
            var ts = DateTime.UtcNow.Subtract(timestamp);
            return ts.TotalSeconds <= Options.ReplayAttackDelayInSeconds;
        }

        /// <summary>
        /// Returns true if the server can generate the same hash as the one the client provided.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="timestamp"></param>
        /// <param name="clientHash"></param>
        /// <returns></returns>
        private static bool ComputeHash(string sharedSecret, DateTime timestamp, string clientHash)
        {
            string hashString;
            var ticks = timestamp.Ticks.ToString(CultureInfo.InvariantCulture);
            var key = Encoding.UTF8.GetBytes(sharedSecret);
            using (var hmac = new HMACSHA256(key))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(ticks));
                hashString = Convert.ToBase64String(hash);
            }
            return hashString.Equals(clientHash);
        }
    }
}
