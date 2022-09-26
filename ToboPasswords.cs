using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace ToboPasswords
{
    public class ToboPasswords
    {
        const string Dir = "ToboPasswords";
        const string FileExt = "tpb"; // Tobo Password Bank

        static bool firstRun = true;
        static bool exit = false;

        public static void Main()
        {
            while (!exit)
                Loop();
        }

        private static void Loop()
        {
            Console.Clear();

            Write("-- TOBO PASSWORDS --");
            if (firstRun)
            {
                firstRun = false;
                Write("Min pass length: " + Encryption.MinPasswordLength);
                Write("Type 'exit' or 'stop' at any time to quit");
            }
            Write();

            if (!Directory.Exists(GetDir()))
                Directory.CreateDirectory(GetDir());

            string[] files = Directory.GetFiles(GetDir(), "*." + FileExt, SearchOption.TopDirectoryOnly);

            if (files.Length > 0)
            {
                Write("Select a bank by number (- to remove), or input a new bank name");

                for (int i = 0; i < files.Length; i++)
                    Write($" {i + 1} - {Path.GetFileName(files[i])}");
            }
            else
            {
                Write("Input a new bank name");
            }

            if (Read(out string input)) // Read() returns true if the user wants to exit
                return;

            if (int.TryParse(input, out int result))
            {
                if (result > 0 && result < files.Length + 1)
                {
                    EnterBank(Path.GetFileName(files[result - 1]));
                }
                else if (result < 0 && -result < files.Length + 1)
                {
                    File.Delete(files[-result - 1]);
                }
                else
                {
                    Write($"{result} is not valid, must be < number of banks");
                    Write("Press enter to return...");
                    Read(out _);
                }
            }
            else
            {
                if (input.Length == 0) return;
                Write($"Created bank '{input}.{FileExt}'");
                EnterBank($"{input}.{FileExt}");
            }
        }


        private static void EnterBank(string bank)
        {
            Write();
            Write($"You are now viewing {bank}");

            string contents = string.Empty;
            string pass = null;

            if (File.Exists(Get(bank)))
            {
                contents = File.ReadAllText(Get(bank));
                if (contents.Length > 0)
                {
                TryPass:;
                    Write($" Please enter the password for {bank}");

                    pass = GetPassword(); // Not using Read() because pass could be 'exit'
                    while (pass.Length < Encryption.MinPasswordLength)
                    {
                        Write($"Password must be more than {Encryption.MinPasswordLength} characters.");
                        pass = GetPassword();
                    }
                
                    contents = Encryption.SimpleDecryptWithPassword(contents, pass);

                    if (contents == null)
                    {
                        Write("Incorrect password.");
                        goto TryPass;
                    }
                    else
                    {
                        string[] lines = contents.Split("\n", StringSplitOptions.RemoveEmptyEntries);
                        for (int i = 1; i < lines.Length; i += 2) // Start at 1 to prevent overflow for trailing \n
                            Write($" - {lines[i - 1]} : {lines[i]}"); // Key and value stored on seperate lines
                    }
                }
            }

            if (contents.Length == 0)
            {
                Write(" This bank is empty. Commands:");
                Write(" - add [key] [value]");
                Write(" - remove [key]");
                Write(" - save [password, if blank use existing]");
                Write(" - list");
                Write(" - return");
                Write(" - exit/stop");
                Write();
            }

            bool saved = false;
            string input;
            while (Read(out input) == false)
            {
                if (input.Length == 0) continue;

                List<string> split = new(ParseText(input, ' ', '\"'));

                if (split[0] == "add" && split.Count == 3)
                {
                    if (split[1].Length == 0 || split[2].Length == 0)
                        continue;

                    if (KeyPosition(contents, split[1]) != -1)
                        continue;

                    contents += $"{split[1]}\n{split[2]}\n";
                    Write($"Added {split[1]} : {split[2]}");
                    Write();
                    saved = false;
                }
                else if (split[0] == "remove" && split.Count == 2)
                {
                    if (split[1].Length == 0 || contents.Length == 0)
                        continue;

                    if (!contents.Contains(split[1]))
                        continue;

                    int keyPos = KeyPosition(contents, split[1]);
                    if (keyPos == -1) continue;

                    contents = RemoveKeyValuePair(contents, keyPos);
                    Write($"Removed {split[1]}");
                    Write();
                    saved = false;
                }
                else if (split[0] == "save" && split.Count < 3)
                {
                    if (contents.Length == 0)
                    {
                        File.WriteAllText(Get(bank), "");
                        saved = true;
                        Write($"Saved empty {bank}");
                        continue;
                    }

                    if (split.Count == 2)
                        pass = split[1];
                    if (pass == null)
                    {
                        Write("Please specify a password");
                        continue;
                    }
                    if (pass.Length < Encryption.MinPasswordLength)
                    {
                        Write($"Password must be more than {Encryption.MinPasswordLength} characters.");
                        continue;
                    }
                    if (contents.Length == 0)
                        continue;
                    File.WriteAllText(Get(bank), Encryption.SimpleEncryptWithPassword(contents, pass));
                    Write($"Saved {bank} {(split.Count == 2 ? "(new password)" : "(existing password)")}");
                    Write();
                    saved = true;
                }
                if (split[0] == "list")
                {
                    Write($"\n{bank}");
                    string[] lines = contents.Split("\n", StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 1; i < lines.Length; i += 2)
                        Write($" - {lines[i - 1]} : {lines[i]}");
                }
                if (split[0] == "return")
                {
                    if (!saved)
                    {
                        Write("You haven't saved your changes, type 'yes' to discard");
                        if (Console.ReadLine() == "yes")
                            return;
                        continue;
                    }
                    return;
                }
            }
        }

        static IEnumerable<string> ParseText(string line, char delimiter, char textQualifier)
        {
            // https://stackoverflow.com/questions/14655023/split-a-string-that-has-white-spaces-unless-they-are-enclosed-within-quotes

            if (string.IsNullOrWhiteSpace(line))
                yield break;

            else
            {
                char prevChar = '\0';
                char nextChar = '\0';
                char currentChar = '\0';

                bool inString = false;

                StringBuilder token = new StringBuilder();

                for (int i = 0; i < line.Length; i++)
                {
                    currentChar = line[i];

                    if (i > 0)
                        prevChar = line[i - 1];
                    else
                        prevChar = '\0';

                    if (i + 1 < line.Length)
                        nextChar = line[i + 1];
                    else
                        nextChar = '\0';

                    if (currentChar == textQualifier && (prevChar == '\0' || prevChar == delimiter) && !inString)
                    {
                        inString = true;
                        continue;
                    }

                    if (currentChar == textQualifier && (nextChar == '\0' || nextChar == delimiter) && inString)
                    {
                        inString = false;
                        continue;
                    }

                    if (currentChar == delimiter && !inString)
                    {
                        yield return token.ToString();
                        token = token.Remove(0, token.Length);
                        continue;
                    }

                    token = token.Append(currentChar);

                }

                yield return token.ToString();

            }
        }

        static int KeyPosition(string contents, string key)
        {
            string[] split = contents.Split("\n", StringSplitOptions.RemoveEmptyEntries);
            if (split.Length < 2)
                return -1;

            int len = 0;

            for (int i = 0; i < split.Length; i += 2)
            {
                if (split[i] == key)
                    return len;
                if (i + 1 >= split.Length) return -1;
                len += split[i].Length + split[i + 1].Length + 2; // \n characters stripped
            }

            return -1;
        }

        static string RemoveKeyValuePair(string contents, int keyPos)
        {
            // keyPos starts at first letter
            int len = 0;
            bool second = false;
            while (keyPos + len < contents.Length)
            {
                if (contents[keyPos + len++] == '\n')
                {
                    if (second == true)
                    {
                        return contents.Remove(keyPos, len);
                    }
                    else
                        second = true;
                }
            }

            return contents.Remove(keyPos);
        }

        static void Write() => Console.WriteLine();
        static void Write(string msg) => Console.WriteLine(msg);

        static bool Read(out string value)
        {
            value = Console.ReadLine();
            exit = value.ToLower() == "exit" || value.ToLower() == "stop";
            return exit;
        }
        static string GetPassword()
        {
            // https://stackoverflow.com/questions/3404421/password-masking-console-application
            string pass = string.Empty;
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            Console.WriteLine();
            return pass;
        }

        static string GetDir() => Comb(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Dir);
        static string Get(string file) => Comb(GetDir(), file);

        #region Combine
        static string Comb(string str1, string str2) => Path.Combine(str1, str2);
        static string Comb(string str1, string str2, string str3) => Path.Combine(str1, str2, str3);
        static string Comb(string str1, string str2, string str3, string str4) => Path.Combine(str1, str2, str3, str4);
        static string Comb(params string[] strs) => Path.Combine(strs);
        #endregion
    }

    public static class Encryption
    {
        private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

        //Preconfigured Encryption Parameters
        public static readonly int BlockBitSize = 128;
        public static readonly int KeyBitSize = 256;

        //Preconfigured Password Key Derivation Parameters
        public static readonly int SaltBitSize = 64;
        public static readonly int Iterations = 10000;
        public static readonly int MinPasswordLength = 4;

        public static string SimpleEncryptWithPassword(string secretMessage, string password,
                                 byte[] nonSecretPayload = null)
        {
            if (string.IsNullOrEmpty(secretMessage))
                throw new ArgumentException("Secret Message Required!", "secretMessage");

            var plainText = Encoding.UTF8.GetBytes(secretMessage);
            var cipherText = SimpleEncryptWithPassword(plainText, password, nonSecretPayload);
            return Convert.ToBase64String(cipherText);
        }

        public static string SimpleDecryptWithPassword(string encryptedMessage, string password,
                                 int nonSecretPayloadLength = 0)
        {
            if (string.IsNullOrWhiteSpace(encryptedMessage))
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            var cipherText = Convert.FromBase64String(encryptedMessage);
            var plainText = SimpleDecryptWithPassword(cipherText, password, nonSecretPayloadLength);
            return plainText == null ? null : Encoding.UTF8.GetString(plainText);
        }

        public static byte[] SimpleEncrypt(byte[] secretMessage, byte[] cryptKey, byte[] authKey, byte[] nonSecretPayload = null)
        {
            //User Error Checks
            if (cryptKey == null || cryptKey.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "cryptKey");

            if (authKey == null || authKey.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "authKey");

            if (secretMessage == null || secretMessage.Length < 1)
                throw new ArgumentException("Secret Message Required!", "secretMessage");

            //non-secret payload optional
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            byte[] cipherText;
            byte[] iv;

            using (var aes = Aes.Create())
            {
                /*
                KeySize = KeyBitSize,
                BlockSize = BlockBitSize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
                */

                aes.KeySize = KeyBitSize;
                aes.BlockSize = BlockBitSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                //Use random IV
                aes.GenerateIV();
                iv = aes.IV;

                using (var encrypter = aes.CreateEncryptor(cryptKey, iv))
                using (var cipherStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(cryptoStream))
                    {
                        //Encrypt Data
                        binaryWriter.Write(secretMessage);
                    }

                    cipherText = cipherStream.ToArray();
                }

            }

            //Assemble encrypted message and add authentication
            using (var hmac = new HMACSHA256(authKey))
            using (var encryptedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(encryptedStream))
                {
                    //Prepend non-secret payload if any
                    binaryWriter.Write(nonSecretPayload);
                    //Prepend IV
                    binaryWriter.Write(iv);
                    //Write Ciphertext
                    binaryWriter.Write(cipherText);
                    binaryWriter.Flush();

                    //Authenticate all data
                    var tag = hmac.ComputeHash(encryptedStream.ToArray());
                    //Postpend tag
                    binaryWriter.Write(tag);
                }
                return encryptedStream.ToArray();
            }

        }

        public static byte[] SimpleDecrypt(byte[] encryptedMessage, byte[] cryptKey, byte[] authKey, int nonSecretPayloadLength = 0)
        {

            //Basic Usage Error Checks
            if (cryptKey == null || cryptKey.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("CryptKey needs to be {0} bit!", KeyBitSize), "cryptKey");

            if (authKey == null || authKey.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("AuthKey needs to be {0} bit!", KeyBitSize), "authKey");

            if (encryptedMessage == null || encryptedMessage.Length == 0)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            using (var hmac = new HMACSHA256(authKey))
            {
                var sentTag = new byte[hmac.HashSize / 8];
                //Calculate Tag
                var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentTag.Length);
                var ivLength = (BlockBitSize / 8);

                //if message length is to small just return null
                if (encryptedMessage.Length < sentTag.Length + nonSecretPayloadLength + ivLength)
                    return null;

                //Grab Sent Tag
                Array.Copy(encryptedMessage, encryptedMessage.Length - sentTag.Length, sentTag, 0, sentTag.Length);

                //Compare Tag with constant time comparison
                var compare = 0;
                for (var i = 0; i < sentTag.Length; i++)
                    compare |= sentTag[i] ^ calcTag[i];

                //if message doesn't authenticate return null
                if (compare != 0)
                    return null;

                using (var aes = Aes.Create())
                {
                    aes.KeySize = KeyBitSize;
                    aes.BlockSize = BlockBitSize;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    //Grab IV from message
                    var iv = new byte[ivLength];
                    Array.Copy(encryptedMessage, nonSecretPayloadLength, iv, 0, iv.Length);

                    using (var decrypter = aes.CreateDecryptor(cryptKey, iv))
                    using (var plainTextStream = new MemoryStream())
                    {
                        using (var decrypterStream = new CryptoStream(plainTextStream, decrypter, CryptoStreamMode.Write))
                        using (var binaryWriter = new BinaryWriter(decrypterStream))
                        {
                            //Decrypt Cipher Text from Message
                            binaryWriter.Write(
                              encryptedMessage,
                              nonSecretPayloadLength + iv.Length,
                              encryptedMessage.Length - nonSecretPayloadLength - iv.Length - sentTag.Length
                            );
                        }
                        //Return Plain Text
                        return plainTextStream.ToArray();
                    }
                }
            }
        }

        public static byte[] SimpleEncryptWithPassword(byte[] secretMessage, string password, byte[] nonSecretPayload = null)
        {
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            //User Error Checks
            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
                throw new ArgumentException(String.Format("Must have a password of at least {0} characters!", MinPasswordLength), "password");

            if (secretMessage == null || secretMessage.Length == 0)
                throw new ArgumentException("Secret Message Required!", "secretMessage");

            var payload = new byte[((SaltBitSize / 8) * 2) + nonSecretPayload.Length];

            Array.Copy(nonSecretPayload, payload, nonSecretPayload.Length);
            int payloadIndex = nonSecretPayload.Length;

            byte[] cryptKey;
            byte[] authKey;
            //Use Random Salt to prevent pre-generated weak password attacks.
            using (var generator = new Rfc2898DeriveBytes(password, SaltBitSize / 8, Iterations))
            {
                var salt = generator.Salt;

                //Generate Keys
                cryptKey = generator.GetBytes(KeyBitSize / 8);

                //Create Non Secret Payload
                Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
                payloadIndex += salt.Length;
            }

            //Deriving separate key, might be less efficient than using HKDF, 
            //but now compatible with RNEncryptor which had a very similar wireformat and requires less code than HKDF.
            using (var generator = new Rfc2898DeriveBytes(password, SaltBitSize / 8, Iterations))
            {
                var salt = generator.Salt;

                //Generate Keys
                authKey = generator.GetBytes(KeyBitSize / 8);

                //Create Rest of Non Secret Payload
                Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
            }

            return SimpleEncrypt(secretMessage, cryptKey, authKey, payload);
        }

        public static byte[] SimpleDecryptWithPassword(byte[] encryptedMessage, string password, int nonSecretPayloadLength = 0)
        {
            //User Error Checks
            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
                throw new ArgumentException(String.Format("Must have a password of at least {0} characters!", MinPasswordLength), "password");

            if (encryptedMessage == null || encryptedMessage.Length == 0)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            var cryptSalt = new byte[SaltBitSize / 8];
            var authSalt = new byte[SaltBitSize / 8];

            //Grab Salt from Non-Secret Payload
            Array.Copy(encryptedMessage, nonSecretPayloadLength, cryptSalt, 0, cryptSalt.Length);
            Array.Copy(encryptedMessage, nonSecretPayloadLength + cryptSalt.Length, authSalt, 0, authSalt.Length);

            byte[] cryptKey;
            byte[] authKey;

            //Generate crypt key
            using (var generator = new Rfc2898DeriveBytes(password, cryptSalt, Iterations))
            {
                cryptKey = generator.GetBytes(KeyBitSize / 8);
            }
            //Generate auth key
            using (var generator = new Rfc2898DeriveBytes(password, authSalt, Iterations))
            {
                authKey = generator.GetBytes(KeyBitSize / 8);
            }

            return SimpleDecrypt(encryptedMessage, cryptKey, authKey, cryptSalt.Length + authSalt.Length + nonSecretPayloadLength);
        }
    }
}
