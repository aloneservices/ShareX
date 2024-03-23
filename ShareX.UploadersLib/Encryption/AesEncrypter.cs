using System.IO;
using System.Linq;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using ShareX.HelpersLib;

namespace ShareX.UploadersLib.Encryption
{
    public class AesEncryptedResult
    {
        public string NonceAndKeyHex { get; set; }
        public Stream Stream { get; set; }
    }

    public static class AesEncrypter
    {
        public static AesEncryptedResult Encrypt(Stream stream)
        {
            var random = new SecureRandom();
            var key = new KeyParameter(random.GenerateSeed(32));
            var parameters = new AeadParameters(key, 128, random.GenerateSeed(12));

            var blockCipher = new GcmBlockCipher(new AesEngine());
            blockCipher.Init(true, parameters);

            var plainBytes = stream.GetBytes();

            var outputSize = blockCipher.GetOutputSize(plainBytes.Length);
            var encryptedData = new byte[outputSize];
            var result = blockCipher.ProcessBytes(plainBytes, 0, plainBytes.Length, encryptedData, 0);
            blockCipher.DoFinal(encryptedData, result);

            var nonceAndKeyHex = Hex.ToHexString(parameters.GetNonce().Concat(key.GetKey()).ToArray());
            return new AesEncryptedResult
            {
                NonceAndKeyHex = nonceAndKeyHex,
                Stream = new MemoryStream(encryptedData)
            };
        }
    }
}