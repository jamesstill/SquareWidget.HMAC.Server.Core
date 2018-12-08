using System.Threading.Tasks;

namespace SquareWidget.HMAC.Server.Core
{
    public abstract class SharedSecretStoreService
    {
        public abstract Task<string> GetSharedSecretAsync(string clientId);
    }
}
