using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security.Cryptography;

namespace NotSoSecure.AspDotNetWrapper
{
    class ViewStateHelper
    {
        public static string[] algorithms = { "MD5", "SHA1", "SHA256", "SHA384", "SHA512"};
        public static int[] hashSizes = { 16, 20, 32, 48, 64 };

        public static string DecodeData(string strValidationKey, string strValidationAlgorithm, byte[] protectedData, string modifier)
        {
            byte[] byteModifier = CryptoUtil.HexToBinary(modifier);
            Array.Reverse(byteModifier);

            int hashSize = ViewStateHelper.hashSizes[Array.IndexOf(ViewStateHelper.algorithms, strValidationAlgorithm)];
            int dataSize = protectedData.Length - hashSize;

            byte[] byteHash = new byte[hashSize];
            Buffer.BlockCopy(protectedData, dataSize, byteHash, 0, hashSize);

            byte[] byteData = new byte[dataSize + byteModifier.Length];
            Buffer.BlockCopy(protectedData, 0, byteData, 0, dataSize);
            Buffer.BlockCopy(byteModifier, 0, byteData, dataSize, byteModifier.Length);

            KeyedHashAlgorithm keyedHashAlgorithm = GetHMACAlgorithm(strValidationAlgorithm, CryptoUtil.HexToBinary(strValidationKey));
            byte[] computedHash= keyedHashAlgorithm.ComputeHash(byteData);

            if (CryptoUtil.BinaryToHex(computedHash) == CryptoUtil.BinaryToHex(byteHash))
            {
                byte[] rawData = new byte[dataSize];
                Buffer.BlockCopy(protectedData, 0, rawData, 0, dataSize);
                return System.Convert.ToBase64String(rawData);
            }
            return "";
        }

        public static KeyedHashAlgorithm GetHMACAlgorithm(string digestMethod, byte[] validationKey)
        {
            switch (digestMethod)
            {
                case "SHA1":
                    return new HMACSHA1(validationKey);
                case "HMACSHA256":
                    return new HMACSHA256(validationKey);
                case "HMACSHA384":
                    return new HMACSHA384(validationKey);
                case "HMACSHA512":
                    return new HMACSHA512(validationKey);
                default:
                    return new HMACSHA256(validationKey);
            }
        }
    }
}
