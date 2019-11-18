using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Web.Security.Cryptography
{
    // Copied from private sub-class in: https://github.com/Microsoft/referencesource/blob/master/System.Web/Security/FormsAuthenticationTicketSerializer.cs
    internal sealed class SerializingBinaryWriter : BinaryWriter
    {
        public SerializingBinaryWriter(Stream output)
            : base(output)
        {
        }

        public override void Write(string value)
        {
            // should never call this method since it will produce wrong results
            throw new NotImplementedException();
        }

        public void WriteBinaryString(string value)
        {
            byte[] bytes = new byte[value.Length * 2];
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                bytes[2 * i] = (byte)c;
                bytes[2 * i + 1] = (byte)(c >> 8);
            }

            Write7BitEncodedInt(value.Length);
            Write(bytes);
        }
    }
}
