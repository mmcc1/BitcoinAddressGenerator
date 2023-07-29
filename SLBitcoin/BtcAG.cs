using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.EC;
using System.Security.Cryptography;

namespace SLBitcoin
{
    public static class BtcAG
    {

        /// <summary>
        /// Generate a full 256bit secure random key
        /// </summary>
        public static KeyPair CreateKeys()
        {
            SecureRandom secRnd = new SecureRandom();

            byte[] max = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40 };
            Org.BouncyCastle.Asn1.X9.X9ECParameters ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");

            KeyPair kps = new KeyPair();

            kps.bytePrivateKey = new byte[32];
            kps.bytePublicAddress = new byte[65];

            byte[] shaResult = ComputeSha256(DateTime.UtcNow.ToString() + DateTime.UtcNow.Ticks.ToString());

            for (int j = 0; j < 32; j++)
                kps.bytePrivateKey[j] = Convert.ToByte((secRnd.Next(1, secRnd.Next(2, int.MaxValue - 256)) + Convert.ToInt32(shaResult[j])) % max[j]);

            Org.BouncyCastle.Math.BigInteger Db = new Org.BouncyCastle.Math.BigInteger(1, kps.bytePrivateKey);

            Org.BouncyCastle.Math.EC.ECPoint dd = ps.G.Multiply(Db);

            byte[] Y = dd.Y.ToBigInteger().ToByteArray();
            Array.Copy(Y, 0, kps.bytePublicAddress, 64 - Y.Length + 1, Y.Length);
            byte[] X = dd.X.ToBigInteger().ToByteArray();
            Array.Copy(X, 0, kps.bytePublicAddress, 32 - X.Length + 1, X.Length);
            kps.bytePublicAddress[0] = 4;

            byte[] rv = new byte[33];
            Array.Copy(kps.bytePrivateKey, 0, rv, 1, 32);
            rv[0] = 0x80;
            kps.strPrivateKey = ByteArrayToBase58Check(rv);

            byte[] shaofpubkey = ComputeSha256(kps.bytePublicAddress);
            RIPEMD160 rip = System.Security.Cryptography.RIPEMD160.Create();

            byte[] _hash160 = rip.ComputeHash(shaofpubkey);

            byte[] hex2 = new byte[21];
            Array.Copy(_hash160, 0, hex2, 1, 20);
            hex2[0] = 0;
            kps.strPublicAddress = ByteArrayToBase58Check(hex2);
            //}

            return kps;
        }

        #region Sha256

        private static byte[] ComputeSha256(string ofwhat)
        {
            UTF8Encoding utf8 = new UTF8Encoding(false);
            return ComputeSha256(utf8.GetBytes(ofwhat));
        }

        private static byte[] ComputeSha256(byte[] ofwhat)
        {
            Sha256Digest sha256 = new Sha256Digest();
            sha256.BlockUpdate(ofwhat, 0, ofwhat.Length);
            byte[] rv = new byte[32];
            sha256.DoFinal(rv, 0);
            return rv;
        }

        #endregion

        private static string ByteArrayToBase58Check(byte[] ba)
        {

            byte[] bb = new byte[ba.Length + 4];
            Array.Copy(ba, bb, ba.Length);
            Sha256Digest bcsha256a = new Sha256Digest();
            bcsha256a.BlockUpdate(ba, 0, ba.Length);
            byte[] thehash = new byte[32];
            bcsha256a.DoFinal(thehash, 0);
            bcsha256a.BlockUpdate(thehash, 0, 32);
            bcsha256a.DoFinal(thehash, 0);

            for (int i = 0; i < 4; i++)
                bb[ba.Length + i] = thehash[i];

            return FromByteArray(bb);
        }

        private static string FromByteArray(byte[] ba)
        {
            Org.BouncyCastle.Math.BigInteger addrremain = new Org.BouncyCastle.Math.BigInteger(1, ba);
            Org.BouncyCastle.Math.BigInteger big0 = new Org.BouncyCastle.Math.BigInteger("0");
            Org.BouncyCastle.Math.BigInteger big58 = new Org.BouncyCastle.Math.BigInteger("58");
            string b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            string rv = "";

            while (addrremain.CompareTo(big0) > 0)
            {
                int d = Convert.ToInt32(addrremain.Mod(big58).ToString());
                addrremain = addrremain.Divide(big58);
                rv = b58.Substring(d, 1) + rv;
            }

            foreach (byte b in ba)
            {
                if (b != 0)
                    break;

                rv = "1" + rv;
            }

            return rv;
        }
    }
}
