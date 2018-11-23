using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Web.Security.Cryptography
{
    // Copied from private sub-class in: https://github.com/Microsoft/referencesource/blob/master/System.Web/Security/FormsAuthenticationTicketSerializer.cs
    internal sealed class SerializingBinaryReader : BinaryReader
    {
        public SerializingBinaryReader(Stream input)
            : base(input)
        {
        }

        public string ReadBinaryString()
        {
            int charCount = Read7BitEncodedInt();
            byte[] bytes = ReadBytes(charCount * 2);

            char[] chars = new char[charCount];
            for (int i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
            }

            return new String(chars);
        }

        public override string ReadString()
        {
            // should never call this method since it will produce wrong results
            throw new NotImplementedException();
        }
    }
}
