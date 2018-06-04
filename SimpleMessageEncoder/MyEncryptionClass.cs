using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;

namespace SimpleMessageEncoder
{
    public static class MyEncryptionClass
    {
        static byte[] Hardsalt = { 11, 22, 33, 44, 53, 77, 199, 22, 205, 13, 213, 33, 86, 34, 98, 12 };

        public static string[] EncryptText(string[] message, string key)
        {
            
            byte[] Key = buildKey(key);
            byte[] Salt = new byte[16];
            new Random().NextBytes(Salt);
            string[] newmessage = new string[message.Length];
            message.CopyTo(newmessage,0);
            string[] Cypher = EncryptLines(newmessage,Key,Salt);
            byte[] combined = MergeKeyWSalt(Key, Salt);
            byte[] HashedKey = SHA256.Create().ComputeHash(combined);
            List<string> Result = new List<string>();
            Result.Add(EncLine(BytestoString(Salt),Key,Hardsalt));
            Result.Add(BytestoString(HashedKey));
            for (int i = 0; i < Cypher.Length; i++)
            {
                Result.Add(Cypher[i]);
            }
            return Result.ToArray();

        }
        public static string[] DecryptText(string[] cyphertext, string key)
        {
            Byte[] Key = buildKey(key);
            byte[] Salt;
            try
            {
                Salt = StringtoBytes(DecLine(cyphertext[0], Key, Hardsalt));
            }
            catch (System.Exception)
            {
                return null;
            }
            byte[] combined = MergeKeyWSalt(Key, Salt);
            byte[] HashedKey = SHA256.Create().ComputeHash(combined);
            if (CheckKeyValidity(HashedKey, StringtoBytes(cyphertext[1])))
            {
                string[] Message = new string[cyphertext.Length-2];
                for (int i = 0; i < Message.Length; i++)
                {
                    Message[i] = cyphertext[i+2];
                }
                return DecryptLines(Message, Key, Salt);
            }
            return null;
        }
        private static string[] DecryptLines(string[] lines, byte[] key, byte[] IV)
        {
            for (int i = 0; i < lines.Length; i++)
            {
                lines[i] = DecLine(lines[i], key, IV);
            }
            return lines;
        }
        private static string[] EncryptLines(string[] lines, byte[] key, byte[] IV)
        {
            for (int i = 0; i < lines.Length; i++)
            {
                lines[i] = EncLine(lines[i], key, IV);
            }
            return lines;
        }
        private static bool CheckKeyValidity(byte[] input, byte[] template)
        {
            if (input.Length != template.Length)
            {
                return false;
            }
            // default false, should only be true if all values match
            bool isEqual = false;
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] == template[i])
                {
                    isEqual = true;
                }
                else
                {
                    // arrays are not the same
                    return false;
                }
            }
            return isEqual;
        }
        private static byte[] MergeKeyWSalt(byte[] Key, byte[] Salt)
        {
            byte[] Result = new byte[Salt.Length + Key.Length];
            for (int i = 0; i < Result.Length; i++)
            {
                if (i < Salt.Length)
                {
                    Result[i] = Salt[i];
                }
                else
                {
                    Result[i] = Key[i - Salt.Length];
                }
            }

            return Result;
        }


        public static string EncLine(string plaintext, byte[] key, byte[] IV)
        {
            if (plaintext == null || plaintext.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (plaintext == null || plaintext.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            using (Aes iAes = Aes.Create())
            {
                iAes.Key = key;
                iAes.IV = IV;
                ICryptoTransform Encryptotron = iAes.CreateEncryptor(key, IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, Encryptotron, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plaintext);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

            }
            return BytestoString(encrypted);
        }
        public static string DecLine(string cyphertext, byte[] key, byte[] IV)
        {
            byte[] Cyphertext = StringtoBytes(cyphertext);
            // Check arguments.
            if (Cyphertext == null || Cyphertext.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(Cyphertext))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
        private static string BytestoString(byte[] bytes)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                result.Append(Convert.ToString(bytes[i], 16).PadLeft(2, '0'));
            }
            return result.ToString();
        }
        private static byte[] StringtoBytes(string Bytestring)
        {
            List<byte> result;
            result = new List<byte>();
            for (int i = 0; i < Bytestring.Length - 1; i += 2)
            {
                char byteX1 = Bytestring[i];
                char byteX0 = Bytestring[i + 1];
                StringBuilder ByteBuilder = new StringBuilder();
                ByteBuilder.Append(byteX1);
                ByteBuilder.Append(byteX0);
                byte CurrentByte = Convert.ToByte(ByteBuilder.ToString(), 16);
                result.Add(CurrentByte);
            }
            return result.ToArray();
        }
        public static byte[] buildKey(string key)
        {
            byte[] res = Encoding.Unicode.GetBytes(key);
            return SHA256.Create().ComputeHash(res);
        }
    }
}