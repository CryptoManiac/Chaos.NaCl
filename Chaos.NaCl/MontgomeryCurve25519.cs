using System;
using System.Diagnostics.Contracts;
using Chaos.NaCl.Internal;
using Chaos.NaCl.Internal.Ed25519Ref10;
using Chaos.NaCl.Internal.Salsa;

namespace Chaos.NaCl
{
    // This class is mainly for compatibility with NaCl's Curve25519 implementation
    // If you don't need that compatibility, use Ed25519.KeyExchange
    public static class MontgomeryCurve25519
    {
        public const int PublicKeySize = 32;
        public const int PrivateKeySize = 32;
        public const int SharedKeySize = 32;

        public static byte[] GetPublicKey(byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException("privateKey");
            if (privateKey.Length != PrivateKeySize)
                throw new ArgumentException("privateKey.Length must be 32");
            var publicKey = new byte[32];
            GetPublicKey(new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
            return publicKey;
        }

        static readonly byte[] _basePoint = new byte[32]
		{
			9, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0 ,0, 0, 0, 0, 0,
			0, 0, 0 ,0, 0, 0, 0, 0,
			0, 0, 0 ,0, 0, 0, 0, 0
		};

        public static void GetPublicKey(ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
        {
            Contract.Requires<ArgumentNullException>(publicKey.Array != null && privateKey.Array != null);
            Contract.Requires<ArgumentException>(publicKey.Count == PublicKeySize && privateKey.Count == PrivateKeySize);

            // hack: abusing publicKey as temporary storage
            // todo: remove hack
            for (int i = 0; i < 32; i++)
            {
                publicKey.Array[publicKey.Offset + i] = privateKey.Array[privateKey.Offset + i];
            }
            ScalarOperations.sc_clamp(publicKey.Array, publicKey.Offset);

            GroupElementP3 A;
            GroupOperations.ge_scalarmult_base(out A, publicKey.Array, publicKey.Offset);
            FieldElement publicKeyFE;
            EdwardsToMontgomeryX(out publicKeyFE, ref A.Y, ref A.Z);
            FieldOperations.fe_tobytes(publicKey.Array, publicKey.Offset, ref publicKeyFE);
        }

        // hashes like the Curve25519 paper says
        internal static void KeyExchangeOutputHashCurve25519Paper(byte[] sharedKey, int offset)
        {
            //c = Curve25519output
            const uint c0 = 'C' | 'u' << 8 | 'r' << 16 | (uint)'v' << 24;
            const uint c1 = 'e' | '2' << 8 | '5' << 16 | (uint)'5' << 24;
            const uint c2 = '1' | '9' << 8 | 'o' << 16 | (uint)'u' << 24;
            const uint c3 = 't' | 'p' << 8 | 'u' << 16 | (uint)'t' << 24;

            Array16<uint> salsaState;
            salsaState.x0 = c0;
            salsaState.x1 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 0);
            salsaState.x2 = 0;
            salsaState.x3 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 4);
            salsaState.x4 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 8);
            salsaState.x5 = c1;
            salsaState.x6 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 12);
            salsaState.x7 = 0;
            salsaState.x8 = 0;
            salsaState.x9 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 16);
            salsaState.x10 = c2;
            salsaState.x11 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 20);
            salsaState.x12 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 24);
            salsaState.x13 = 0;
            salsaState.x14 = ByteIntegerConverter.LoadLittleEndian32(sharedKey, offset + 28);
            salsaState.x15 = c3;
            SalsaCore.Salsa(out salsaState, ref salsaState, 20);

            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 0, salsaState.x0);
            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 4, salsaState.x1);
            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 8, salsaState.x2);
            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 12, salsaState.x3);
            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 16, salsaState.x4);
            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 20, salsaState.x5);
            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 24, salsaState.x6);
            ByteIntegerConverter.StoreLittleEndian32(sharedKey, offset + 28, salsaState.x7);
        }

        private static readonly byte[] _zero16 = new byte[16];

        // hashes like the NaCl paper says instead i.e. HSalsa(x,0)
        internal static void KeyExchangeOutputHashNaCl(byte[] sharedKey, int offset)
        {
            Salsa20.HSalsa20(sharedKey, offset, sharedKey, offset, _zero16, 0);
        }

        public static byte[] KeyExchange(byte[] publicKey, byte[] privateKey)
        {
            Contract.Requires<ArgumentNullException>(publicKey != null && privateKey != null);

            var sharedKey = new byte[SharedKeySize];
            KeyExchange(new ArraySegment<byte>(sharedKey), new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
            return sharedKey;
        }

        public static void KeyExchange(ArraySegment<byte> sharedKey, ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
        {
            Contract.Requires<ArgumentNullException>(sharedKey.Array != null && publicKey.Array != null && privateKey.Array != null);
            Contract.Requires<ArgumentException>(sharedKey.Count == SharedKeySize && publicKey.Count == PublicKeySize && privateKey.Count == PrivateKeySize);

            MontgomeryOperations.scalarmult(sharedKey.Array, sharedKey.Offset, privateKey.Array, privateKey.Offset, publicKey.Array, publicKey.Offset);
            KeyExchangeOutputHashNaCl(sharedKey.Array, sharedKey.Offset);
        }

        internal static void EdwardsToMontgomeryX(out FieldElement montgomeryX, ref FieldElement edwardsY, ref FieldElement edwardsZ)
        {
            FieldElement tempX, tempZ;
            FieldOperations.fe_add(out tempX, ref edwardsZ, ref edwardsY);
            FieldOperations.fe_sub(out tempZ, ref edwardsZ, ref edwardsY);
            FieldOperations.fe_invert(out tempZ, ref tempZ);
            FieldOperations.fe_mul(out montgomeryX, ref tempX, ref tempZ);
        }
    }
}
