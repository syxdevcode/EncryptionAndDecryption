using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAndDecryptionLibary
{
    public static class SecurityHelper
    {
        /// <summary>
        /// 取得Hash值
        /// </summary>
        /// <param name="value"></param>
        /// <param name="hashAlgorithm">hash算法</param>
        /// <returns>hash bytes array</returns>
        public static byte[] ToHash(this byte[] value, HashAlgorithm hashAlgorithm)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (hashAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }
            using (hashAlgorithm)
            {
                return hashAlgorithm.ComputeHash(value);
            }
        }

        /// <summary>
        /// MD5摘要算法
        /// </summary>
        /// <param name="value"></param>
        /// <returns>128 bits,16 byte array</returns>
        public static byte[] ToMD5(this byte[] value)
        {
            return value.ToHash(MD5.Create());
        }

        /// <summary>
        /// SHA1哈希算法
        /// </summary>
        /// <param name="value"></param>
        /// <returns>160 bits,20 byte array</returns>
        public static byte[] ToSHA1(this byte[] value)
        {
            return value.ToHash(SHA1.Create());
        }

        /// <summary>
        /// SHA256哈希算法
        /// </summary>
        /// <param name="value"></param>
        /// <returns>256 bits,32 byte array</returns>
        public static byte[] ToSHA256(this byte[] value)
        {
            return value.ToHash(SHA256.Create());
        }

        /// <summary>
        /// HMACSHA1算法
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key"></param>
        /// <returns>160 bits,20 byte array</returns>
        public static byte[] ToHMACSHA1(this byte[] value, byte[] key)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException(nameof(key));
            }
            return value.ToHash(new HMACSHA1(key));
        }

        /// <summary>
        ///  AES加密
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key">128bit,192bit,125bit</param>
        /// <returns></returns>
        public static byte[] AESEncrypt(this byte[] value, byte[] key)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException(nameof(key));
            }
            using (var symmetricAlgorithm = Aes.Create())
            {
                symmetricAlgorithm.Key = key;
                symmetricAlgorithm.Mode = CipherMode.ECB;
                symmetricAlgorithm.Padding = PaddingMode.PKCS7;
                //加密
                using (var encryptor = symmetricAlgorithm.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(value, 0, value.Length);
                }
            }
        }

        /// <summary>
        ///  AES解密
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key">128bit,192bit,125bit</param>
        /// <returns></returns>
        public static byte[] AESDecrypt(this byte[] value, byte[] key)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException(nameof(key));
            }
            using (var symmetricAlgorithm = Aes.Create())
            {
                symmetricAlgorithm.Key = key;
                symmetricAlgorithm.Mode = CipherMode.ECB;
                symmetricAlgorithm.Padding = PaddingMode.PKCS7;

                //解密
                using (var decryptor = symmetricAlgorithm.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(value, 0, value.Length);
                }
            }
        }

        /// <summary>
        ///  RSA加密
        /// </summary>
        /// <param name="value"></param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public static byte[] RSAEncrypt(this byte[] value, string publicKey)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (string.IsNullOrEmpty(publicKey) == true)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            using (var asymmetricAlgorithm = new RSACryptoServiceProvider())
            {
                asymmetricAlgorithm.FromXmlString(publicKey);
                return asymmetricAlgorithm.Encrypt(value, false);
            }
        }

        /// <summary>
        ///  AES解密
        /// </summary>
        /// <param name="value"></param>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        public static byte[] RSADecrypt(this byte[] value, string privateKey)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (string.IsNullOrEmpty(privateKey) == true)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            using (var asymmetricAlgorithm = new RSACryptoServiceProvider())
            {
                asymmetricAlgorithm.FromXmlString(privateKey);
                return asymmetricAlgorithm.Decrypt(value, false);
            }
        }

        /// <summary>
        /// RSA数字签名
        /// </summary>
        /// <param name="value"></param>
        /// <param name="privateKey">私钥</param>
        /// <returns>数字签名</returns>
        public static byte[] RSASignature(this byte[] value, string privateKey)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (string.IsNullOrEmpty(privateKey) == true)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            using (var asymmetricAlgorithm = new RSACryptoServiceProvider())
            {
                asymmetricAlgorithm.FromXmlString(privateKey);
                return asymmetricAlgorithm.SignData(value, SHA1.Create());
            }
        }

        /// <summary>
        /// RSA数字签名验证
        /// </summary>
        /// <param name="value"></param>
        /// <param name="publicKey">公钥</param>
        /// <param name="signature">数字签名</param>
        /// <returns></returns>
        public static bool RSASignatureVerify(this byte[] value, string publicKey, byte[] signature)
        {
            using (var asymmetricAlgorithm = new RSACryptoServiceProvider())
            {
                asymmetricAlgorithm.FromXmlString(publicKey);
                return asymmetricAlgorithm.VerifyData(value, SHA1.Create(), signature);
            }
        }

        /// <summary>
        /// 构造伪随机数
        /// </summary>
        /// <param name="byteCount">长度</param>
        /// <returns></returns>
        public static byte[] BuildPseudoRandomNumber(byte byteCount)
        {
            using (RandomNumberGenerator randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[byteCount];
                randomNumberGenerator.GetBytes(bytes);
                return bytes;
            }
        }

        /// <summary>
        /// bytes转16进制
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string ToHex(this byte[] value)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            return BitConverter.ToString(value).Replace("-", "");
        }

        /// <summary>
        /// 16进制字符串还原为bytes
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] HexToBytes(this string value)
        {
            if (string.IsNullOrEmpty(value) == true)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (value.Length % 2 != 0)
            {
                throw new IndexOutOfRangeException("invalid hex string");
            }
            var bytes = new byte[value.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// bytes转base64
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string ToBase64(this byte[] value)
        {
            if (value == null || value.Length == 0)
            {
                throw new ArgumentNullException(nameof(value));
            }
            return Convert.ToBase64String(value);
        }

        /// <summary>
        /// 字符串转bytes
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encoding">编码格式，默认采用UTF8编码</param>
        /// <returns></returns>
        public static byte[] ToBytes(this string value, Encoding encoding = null)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }
            return encoding.GetBytes(value);
        }

        /// <summary>
        /// bytes转字符串
        /// </summary>
        /// <param name="value"></param>
        /// <param name="encoding">编码格式，默认采用UTF8编码</param>
        /// <returns></returns>
        public static string GetString(this byte[] value, Encoding encoding = null)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }
            return encoding.GetString(value);
        }

        /// <summary>
        /// 基于HMAC-SHA-1的OTP
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="counter">计数器</param>
        /// <param name="length">otp的长度</param>
        /// <returns></returns>
        public static string HOTP(byte[] key, byte[] counter, int length = 6)
        {
            var hmac = counter.ToHMACSHA1(key);

            var offset = hmac[hmac.Length - 1] & 0xF;

            var b1 = (hmac[offset] & 0x7F) << 24;
            var b2 = (hmac[offset + 1] & 0xFF) << 16;
            var b3 = (hmac[offset + 2] & 0xFF) << 8;
            var b4 = (hmac[offset + 3] & 0xFF);

            var code = b1 | b2 | b3 | b4;

            var value = code % (int)Math.Pow(10, length);

            return value.ToString().PadLeft(length, '0');
        }

        /// <summary>
        /// 基于时间的OTP
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="step">步长</param>
        /// <param name="length">otp的长度</param>
        /// <returns></returns>
        public static string TOTP(byte[] key, int step = 60, int length = 6)
        {
            var unixTime = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            var counter = ((int)unixTime) / step;
            var counterBytes = BitConverter.GetBytes(counter);
            return HOTP(key, counterBytes, length);
        }
    }
}
