using Microsoft.AspNetCore.Authentication;

namespace SquareWidget.HMAC.Server.Core
{
    public class HmacAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string HashHeaderName { get; set; } = "Hash";
        public string TimestampHeaderName { get; set; } = "Timestamp";
        public int ReplayAttackDelayInSeconds { get; set; } = 15;
    }
}
