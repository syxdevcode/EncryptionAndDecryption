using EncryptionAndDecryptionLibary;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionAndDecryptionConsoleDemo
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string inputStr = "中国，china no.1;... ..;";

            #region Base64加密/解密

            Console.WriteLine("--------Base64加密/解密---------");
            string encryptStr = EncryptUtils.Base64Encrypt(inputStr);

            Console.WriteLine("Base64加密串：" + encryptStr);

            string decryptStr = EncryptUtils.Base64Decrypt(encryptStr);

            Console.WriteLine("Base64解密串：" + decryptStr);

            #endregion Base64加密/解密

            #region DES加密/解密

            Console.WriteLine("--------DES加密/解密---------");
            string desKey = "12312312";
            string ivKey = "11111114";
            encryptStr = EncryptUtils.DESEncrypt(inputStr, desKey);
            Console.WriteLine("DES加密串：" + encryptStr);

            Console.WriteLine("DES解密串：" + EncryptUtils.DESDecrypt(encryptStr, desKey));

            encryptStr = EncryptUtils.DESEncrypt(inputStr, desKey, ivKey);
            Console.WriteLine("DES加密串：" + encryptStr);

            Console.WriteLine("DES解密串：" + EncryptUtils.DESDecrypt(encryptStr, desKey, ivKey));

            #endregion DES加密/解密

            #region 3DES加密/解密  key要求必须为字符串长度为24字节Base64编码之后的byte数组

            Console.WriteLine("--------3DES加密/解密---------");
            System.Text.Encoding utf8 = System.Text.Encoding.UTF8;

            //key为abcdefghijklmnopqrstuvwx的Base64编码  
            byte[] key = Convert.FromBase64String("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4");

            //Base64的编码
            // 编码：
            byte[] bytes = Encoding.Default.GetBytes("要转换的字符要转换的字符");
            string str = Convert.ToBase64String(bytes);

            // 解码：
            byte[] outputb = Convert.FromBase64String(str);
            string orgStr = Encoding.Default.GetString(outputb);


            byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };      //当模式为ECB时，IV无用  
            byte[] data = utf8.GetBytes("中国ABCabc123");
            System.Console.WriteLine("ECB模式:");
            byte[] str1 = EncryptUtils.DES3EncryptECB(outputb, iv, data);
            byte[] str2 = EncryptUtils.DES3DecryptECB(outputb, iv, str1);
            System.Console.WriteLine(Convert.ToBase64String(str1));
            System.Console.WriteLine(System.Text.Encoding.UTF8.GetString(str2));
            System.Console.WriteLine();
            System.Console.WriteLine("CBC模式:");
            byte[] str3 = EncryptUtils.DES3EncryptCBC(key, iv, data);
            byte[] str4 = EncryptUtils.DES3DecryptCBC(key, iv, str3);
            System.Console.WriteLine(Convert.ToBase64String(str3));
            System.Console.WriteLine(utf8.GetString(str4));
            System.Console.WriteLine();


            string tripledes = EncryptUtils.TripleDesBase64Encode(str, iv, bytes);
            Console.WriteLine(tripledes);
            #endregion 3DES加密/解密

            #region AES加密/解密

            Console.WriteLine("------------AES加密/解密--------------");
            string genKey = EncryptUtils.AESGenerateKey(32);

            string encryptString = "待加密密文123abc!@#%$?，“”。1231asd";
            Console.WriteLine("要操作的字符串：" + encryptString);

            string encrypt = EncryptUtils.AESEncryptECB(encryptString, genKey);
            Console.WriteLine(encrypt);
            string decrypt = EncryptUtils.AESDecryptECB(encrypt, genKey);
            Console.WriteLine(decrypt);

            string aesiv = EncryptUtils.AESGenerateKey(16);
            encrypt = EncryptUtils.AESEncrypt(encryptString, genKey, aesiv);
            Console.WriteLine(encrypt);

            decrypt = EncryptUtils.AESDecrypt(encrypt, genKey, aesiv);
            Console.WriteLine(decrypt);
            
            #region msdn例子
            try
            {

                string original = "Here is some data to encrypt!";

                // Create a new instance of the Rijndael
                // class.  This generates a new key and initialization 
                // vector (IV).
                using (Rijndael myRijndael = Rijndael.Create())
                {
                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptUtils.EncryptStringToBytes(original, myRijndael.Key, myRijndael.IV);

                    // Decrypt the bytes to a string.
                    string roundtrip = EncryptUtils.DecryptStringFromBytes(encrypted, myRijndael.Key, myRijndael.IV);

                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", original);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }

            #endregion
            
            #endregion


            Console.ReadLine();
        }
    }
}