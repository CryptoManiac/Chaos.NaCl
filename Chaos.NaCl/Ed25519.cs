﻿using System;
using System.Diagnostics.Contracts;
using Chaos.NaCl.Internal.Ed25519Ref10;

namespace Chaos.NaCl
{
    public static class Ed25519
    {
        /// <summary>
        /// Public Keys are 32 byte values. All possible values of this size a valid.
        /// </summary>
        public const int PublicKeySize = 32;
        /// <summary>
        /// Signatures are 64 byte values
        /// </summary>
        public const int SignatureSize = 64;
        /// <summary>
        /// Private key seeds are 32 byte arbitrary values. This is the form that should be generated and stored.
        /// </summary>
        public const int PrivateKeySeedSize = 32;
        /// <summary>
        /// A 64 byte expanded form of private key. This form is used internally to improve performance
        /// </summary>
        public const int ExpandedPrivateKeySize = 32 * 2;
        /// <summary>
        /// Shared secret key, derived from the public data.
        /// </summary>
        public const int SharedKeySize = 32;

        /// <summary>
        /// Verify Ed25519 signature
        /// </summary>
        /// <param name="signature">Signature bytes</param>
        /// <param name="message">Message</param>
        /// <param name="publicKey">Public key</param>
        /// <returns>True if signature is valid, false if it's not</returns>
        public static bool Verify(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> publicKey)
        {
            Contract.Requires<ArgumentException>(signature.Count == SignatureSize && publicKey.Count == PublicKeySize);

            return Ed25519Operations.crypto_sign_verify(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, publicKey.Array, publicKey.Offset);
        }

        /// <summary>
        /// Verify Ed25519 signature
        /// </summary>
        /// <param name="signature">Signature bytes</param>
        /// <param name="message">Message</param>
        /// <param name="publicKey">Public key</param>
        /// <returns>True if signature is valid, false if it's not</returns>
        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            Contract.Requires<ArgumentNullException>(signature != null && message != null && publicKey != null);
            Contract.Requires<ArgumentException>(signature.Length == SignatureSize && publicKey.Length == PublicKeySize);

            return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, message.Length, publicKey, 0);
        }

        /// <summary>
        /// Create new Ed25519 signature
        /// </summary>
        /// <param name="signature">Buffer for signature</param>
        /// <param name="message">Message bytes</param>
        /// <param name="expandedPrivateKey">Expanded form of private key</param>
        public static void Sign(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> expandedPrivateKey)
        {
            Contract.Requires<ArgumentNullException>(signature.Array != null && message.Array != null && expandedPrivateKey.Array != null);
            Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize);

            Ed25519Operations.crypto_sign(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, expandedPrivateKey.Array, expandedPrivateKey.Offset);
        }

        /// <summary>
        /// Create new Ed25519 signature
        /// </summary>
        /// <param name="signature">Buffer for signature</param>
        /// <param name="message">Message bytes</param>
        /// <param name="expandedPrivateKey">Expanded form of private key</param>
        public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)
        {
            Contract.Requires<ArgumentNullException>(message != null && expandedPrivateKey != null);
            Contract.Requires<ArgumentException>(expandedPrivateKey.Length == ExpandedPrivateKeySize);

            var signature = new byte[SignatureSize];
            Sign(new ArraySegment<byte>(signature), new ArraySegment<byte>(message), new ArraySegment<byte>(expandedPrivateKey));
            return signature;
        }

        /// <summary>
        /// Calculate public key from private key seed
        /// </summary>
        /// <param name="privateKeySeed">Private key seed value</param>
        /// <returns></returns>
        public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
        {
            Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);

            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(privateKey);
            return publicKey;
        }

        /// <summary>
        /// Calculate expanded form of private key from the key seed.
        /// </summary>
        /// <param name="privateKeySeed">Private key seed value</param>
        /// <returns>Expanded form of the private key</returns>
        public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
        {
            Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);

            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(publicKey);
            return privateKey;
        }

        /// <summary>
        /// Calculate key pair from the key seed.
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="expandedPrivateKey">Expanded form of the private key</param>
        /// <param name="privateKeySeed">Private key seed value</param>
        public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)
        {
            Contract.Requires<ArgumentNullException>(privateKeySeed != null);
            Contract.Requires<ArgumentException>(privateKeySeed.Length == PrivateKeySeedSize);

            var pk = new byte[PublicKeySize];
            var sk = new byte[ExpandedPrivateKeySize];

            Ed25519Operations.crypto_sign_keypair(pk, 0, sk, 0, privateKeySeed, 0);
            publicKey = pk;
            expandedPrivateKey = sk;
        }

        /// <summary>
        /// Calculate key pair from the key seed.
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="expandedPrivateKey">Expanded form of the private key</param>
        /// <param name="privateKeySeed">Private key seed value</param>
        public static void KeyPairFromSeed(ArraySegment<byte> publicKey, ArraySegment<byte> expandedPrivateKey, ArraySegment<byte> privateKeySeed)
        {
            Contract.Requires<ArgumentNullException>(publicKey.Array != null && expandedPrivateKey.Array != null && privateKeySeed.Array != null);
            Contract.Requires<ArgumentException>(expandedPrivateKey.Count == ExpandedPrivateKeySize && privateKeySeed.Count == PrivateKeySeedSize);
            Contract.Requires<ArgumentException>(publicKey.Count == PublicKeySize);

            Ed25519Operations.crypto_sign_keypair(
                publicKey.Array, publicKey.Offset,
                expandedPrivateKey.Array, expandedPrivateKey.Offset,
                privateKeySeed.Array, privateKeySeed.Offset);
        }

        [Obsolete("Needs more testing")]
        public static byte[] KeyExchange(byte[] publicKey, byte[] privateKey)
        {
            Contract.Requires<ArgumentNullException>(publicKey != null && privateKey != null);

            var sharedKey = new byte[SharedKeySize];
            KeyExchange(new ArraySegment<byte>(sharedKey), new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
            return sharedKey;
        }

        [Obsolete("Needs more testing")]
        public static void KeyExchange(ArraySegment<byte> sharedKey, ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
        {
            Contract.Requires<ArgumentNullException>(sharedKey.Array != null && publicKey.Array != null && privateKey.Array != null);
            Contract.Requires<ArgumentException>(sharedKey.Count == SharedKeySize && publicKey.Count == PublicKeySize && privateKey.Count == ExpandedPrivateKeySize);

            FieldElement montgomeryX, edwardsY, edwardsZ, sharedMontgomeryX;
            FieldOperations.fe_frombytes(out edwardsY, publicKey.Array, publicKey.Offset);
            FieldOperations.fe_1(out edwardsZ);
            MontgomeryCurve25519.EdwardsToMontgomeryX(out montgomeryX, ref edwardsY, ref edwardsZ);
            byte[] h = Sha512.Hash(privateKey.Array, privateKey.Offset, 32);//ToDo: Remove alloc
            ScalarOperations.sc_clamp(h, 0);
            MontgomeryOperations.scalarmult(out sharedMontgomeryX, h, 0, ref montgomeryX);
            CryptoBytes.Wipe(h);
            FieldOperations.fe_tobytes(sharedKey.Array, sharedKey.Offset, ref sharedMontgomeryX);
            MontgomeryCurve25519.KeyExchangeOutputHashNaCl(sharedKey.Array, sharedKey.Offset);
        }
    }
}