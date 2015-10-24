using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAndDecryptionLibary
{
    public class RSAEncryptUtils
    {
        #region 生成密钥对

        /// <summary>
        /// 生成密钥
        /// </summary>
        public RSAKey GenerateRSAKey()
        {
            RSAKey RSAKEY = new RSAKey();
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAKEY.PrivateKey = RSA.ToXmlString(true);    //生成私钥
            RSAKEY.PublicKey = RSA.ToXmlString(false);    //生成公钥
            RSA.Clear();
            return RSAKEY;
        }

        #endregion

        #region 加解密

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="dataToEncrypt">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public string Encrypt(string dataToEncrypt, string publicKey)
        {
            Encoding encoder = Encoding.UTF8;
            byte[] _dataToEncrypt = encoder.GetBytes(dataToEncrypt);
            return this.Encrypt(_dataToEncrypt, publicKey);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="dataToEncrypt">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        public string Encrypt(byte[] dataToEncrypt, string publicKey)
        {
            using (RSACryptoServiceProvider RSA = this.CreateEncryptRSA(publicKey))
            {
                byte[] encryptedData = RSA.Encrypt(dataToEncrypt, false);
                return this.BytesToHexString(encryptedData);
            }
        }

        /// <summary>
        /// 根据安全证书加密
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="certfile"></param>
        /// <returns></returns>
        public string X509CertEncrypt(string dataToEncrypt, string certfile)
        {
            Encoding encoder = Encoding.UTF8;
            byte[] _dataToEncrypt = encoder.GetBytes(dataToEncrypt);
            return this.X509CertEncrypt(_dataToEncrypt, certfile);
        }

        /// <summary>
        /// 根据安全证书加密
        /// </summary>
        /// <param name="dataToEncrypt">待加密数据</param>
        /// <param name="certfile">安全证书</param>
        /// <returns></returns>
        public string X509CertEncrypt(byte[] dataToEncrypt, string certfile)
        {
            if (!File.Exists(certfile))
            {
                throw new ArgumentNullException(certfile, "加密证书未找到");
            }
            using (RSACryptoServiceProvider RSA = this.X509CertCreateEncryptRSA(certfile))
            {
                byte[] encryptedData = RSA.Encrypt(dataToEncrypt, false);
                return this.BytesToHexString(encryptedData);
            }
        }


        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        public string Decrypt(string encryptedData, string privateKey)
        {
            using (RSACryptoServiceProvider RSA = this.CreateDecryptRSA(privateKey))
            {
                Encoding encoder = Encoding.UTF8;
                byte[] _encryptedData = HexStringToBytes(encryptedData);
                byte[] decryptedData = RSA.Decrypt(_encryptedData, false);
                return encoder.GetString(decryptedData);
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="keyfile">私钥文件</param>
        /// <param name="password">访问私钥文件密码</param>
        /// <returns></returns>
        public string X509CertDecrypt(string encryptedData, string keyfile, string password)
        {
            if (!File.Exists(keyfile))
            {
                throw new ArgumentNullException(keyfile, "解密证书未找到");
            }
            using (RSACryptoServiceProvider RSA = this.X509CertCreateDecryptRSA(keyfile, password))
            {
                Encoding encoder = Encoding.UTF8;
                byte[] _encryptedData = HexStringToBytes(encryptedData);
                byte[] decryptedData = RSA.Decrypt(_encryptedData, false);
                return encoder.GetString(decryptedData);
            }
        }

        #endregion

        #region 创建加解密RSA

        /// <summary>
        /// 创建加密RSA
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <returns></returns>
        private RSACryptoServiceProvider CreateEncryptRSA(string publicKey)
        {
            try
            {
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.FromXmlString(publicKey);
                return RSA;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 创建解密RSA
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        private RSACryptoServiceProvider CreateDecryptRSA(string privateKey)
        {
            try
            {
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.FromXmlString(privateKey);
                return RSA;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 根据安全证书创建加密RSA
        /// </summary>
        /// <param name="certfile">公钥文件</param>
        /// <returns></returns>
        private RSACryptoServiceProvider X509CertCreateEncryptRSA(string certfile)
        {
            try
            {
                X509Certificate2 x509Cert = new X509Certificate2(certfile);
                RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)x509Cert.PublicKey.Key;
                return RSA;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 根据私钥文件创建解密RSA
        /// </summary>
        /// <param name="keyfile">私钥文件</param>
        /// <param name="password">访问含私钥文件的密码</param>
        /// <returns></returns>
        private RSACryptoServiceProvider X509CertCreateDecryptRSA(string keyfile, string password)
        {
            try
            {
                X509Certificate2 x509Cert = new X509Certificate2(keyfile, password);
                RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)x509Cert.PrivateKey;
                return RSA;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        #endregion

        #region 数据转换

        /// <summary>
        /// Bytes to string
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public string BytesToHexString(byte[] parameters)
        {
            StringBuilder hexString = new StringBuilder(64);
            for (int i = 0; i < parameters.Length; i++)
            {
                hexString.Append(String.Format("{0:x2}", parameters[i]));
            }
            return hexString.ToString();
        }
        /// <summary>
        /// string to Bytes
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public byte[] HexStringToBytes(string hex)
        {
            if (hex.Length == 0)
            {
                return new byte[] { 0 };
            }

            if (hex.Length % 2 == 1)
            {
                hex = "0" + hex;
            }

            byte[] result = new byte[hex.Length / 2];

            for (int i = 0; i < hex.Length / 2; i++)
            {
                result[i] = byte.Parse(hex.Substring(2 * i, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return result;
        }

        #endregion
    }
}
