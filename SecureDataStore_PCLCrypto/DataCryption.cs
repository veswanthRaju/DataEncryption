using System.Text;
using PCLCrypto;

namespace SecureDataStore_PCLCrypto
{
    class DataCryption
    {
        /// <summary>    
        /// Creates Salt with given length in bytes.    
        /// </summary>    
        /// <param name="lengthInBytes">No. of bytes</param>    
        /// <returns></returns>    
        public static byte[] CreateSalt(int lengthInBytes)
        {
            return WinRTCrypto.CryptographicBuffer.GenerateRandom(lengthInBytes);
        }

        /// <summary>    
        /// Encrypts given data using symmetric algorithm AES    
        /// </summary>    
        /// <param name="data">Data to encrypt</param>    
        /// <param name="password">Password</param>    
        /// <param name="salt">Salt</param>    
        /// <returns>Encrypted bytes</returns>    
        public static byte[] EncryptData(string data, string password, byte[] salt)
        {
            byte[] key = CreateDerivedKey(password, salt);

            var aes = WinRTCrypto.SymmetricKeyAlgorithmProvider
                                 .OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            var symetricKey = aes.CreateSymmetricKey(key);
            return WinRTCrypto.CryptographicEngine
                              .Encrypt(symetricKey, Encoding.UTF8.GetBytes(data));
        }

        /// <summary>    
        /// Decrypts given bytes using symmetric alogrithm AES    
        /// </summary>    
        /// <param name="data">data to decrypt</param>    
        /// <param name="password">Password used for encryption</param>    
        /// <param name="salt">Salt used for encryption</param>    
        /// <returns></returns>    
        public static string DecryptData(byte[] data, string password, byte[] salt)
        {
            byte[] key = CreateDerivedKey(password, salt);

            var aes = WinRTCrypto.SymmetricKeyAlgorithmProvider
                                 .OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            var symetricKey = aes.CreateSymmetricKey(key);
            var bytes = WinRTCrypto.CryptographicEngine.Decrypt(symetricKey, data);
            return Encoding.UTF8.GetString(bytes, 0, bytes.Length);
        }
        
        /// <summary>    
        /// Creates a derived key from a comnination     
        /// </summary>    
        /// <param name="password"></param>    
        /// <param name="salt"></param>    
        /// <param name="keyLengthInBytes"></param>    
        /// <param name="iterations"></param>    
        /// <returns></returns>    
        public static byte[] CreateDerivedKey
            (string password, byte[] salt, int keyLengthInBytes = 32, int iterations = 1000)
        {
            return NetFxCrypto.DeriveBytes.GetBytes(password, salt, iterations, keyLengthInBytes);
        }
    }
}