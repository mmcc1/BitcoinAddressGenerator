using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.EC;
using System.Security.Cryptography;

namespace SLBitcoin
{
    [Serializable]
    public class KeyPair
    {
        public string strPublicAddress;
        public byte[] bPublicAddress;
        public string strPrivateKey;
        public byte[] bytePublicAddress;
        public byte[] bytePrivateKey;
    }

    public class BitcoinAddressGenerator
    {
        private Int64 nonce;
        private string uSalt;
        private byte[] privKey;
        private byte[] pubaddr;
        private byte addressType = 0;
        private int[] maxInt = new int[] { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 64 };
        private byte[] max = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40 };
        private byte min = 0x01;
        SecureRandom secRnd;
        List<KeyPair> keyPair;

        public BitcoinAddressGenerator()
        {
            secRnd = new SecureRandom();
            keyPair = new List<KeyPair>();
        }

        public List<KeyPair> CreateKeys(int _numKeys)
        {
            for (int i = 0; i < _numKeys; i++)
            {
                GenerateKey();
                ComputePublicKey();
                KeyPair kP = new KeyPair();
                kP.strPublicAddress = GetAddressBase58();
                kP.strPrivateKey = PrivateKeyBase58();
                kP.bytePublicAddress = pubaddr;
                kP.bytePrivateKey = privKey;
                BitcoinUtils.B58Decode(kP.strPublicAddress, ref kP.bPublicAddress);

                keyPair.Add(kP);
            }

            privKey = null;
            pubaddr = null;

            return keyPair;
        }

        public List<KeyPair> CreateKeys(int _numKeys, List<byte[]> privKeys)
        {
            for (int i = 1; i < _numKeys; i++)
            {
                privKey = privKeys[i];
                ComputePublicKey();
                KeyPair kP = new KeyPair();
                kP.strPublicAddress = GetAddressBase58();
                kP.strPrivateKey = PrivateKeyBase58();
                kP.bytePublicAddress = pubaddr;
                kP.bytePrivateKey = privKey;
                BitcoinUtils.B58Decode(kP.strPublicAddress, ref kP.bPublicAddress);

                keyPair.Add(kP);
            }

            privKey = null;
            pubaddr = null;

            return keyPair;
        }

        /// <summary>
        /// Generate a full 256 secure random key
        /// </summary>
        private void GenerateKey()
        {
            privKey = new byte[32];
            uSalt = DateTime.UtcNow.ToString();
            byte[] shaResult = ComputeSha256(uSalt + DateTime.UtcNow.Ticks.ToString());
            
            bool ok = false;

            while(!ok)
            {
                try
                {
                    for (int i = 0; i < 32; i++)
                    {
                        privKey[i] = Convert.ToByte((secRnd.Next(1, secRnd.Next(2, int.MaxValue)) + Convert.ToInt32(shaResult[i])) % max[i]);
                    }

                    ok = true;
                }
                catch(Exception ex)
                {
                    //overflow...repeat until its ok...
                }
            }
        }

        #region Sha256

        private byte[] ComputeSha256(string ofwhat)
        {
            UTF8Encoding utf8 = new UTF8Encoding(false);
            return ComputeSha256(utf8.GetBytes(ofwhat));
        }

        private byte[] ComputeSha256(byte[] ofwhat)
        {
            Sha256Digest sha256 = new Sha256Digest();
            sha256.BlockUpdate(ofwhat, 0, ofwhat.Length);
            byte[] rv = new byte[32];
            sha256.DoFinal(rv, 0);
            return rv;
        }

        #endregion


        private void ComputePublicKey()
        {
            var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            ECPoint point = ps.G;

            Org.BouncyCastle.Math.BigInteger Db = new Org.BouncyCastle.Math.BigInteger(1, privKey);
            ECPoint dd = point.Multiply(Db);

            pubaddr = new byte[65];
            byte[] Y = dd.Y.ToBigInteger().ToByteArray();
            Array.Copy(Y, 0, pubaddr, 64 - Y.Length + 1, Y.Length);
            byte[] X = dd.X.ToBigInteger().ToByteArray();
            Array.Copy(X, 0, pubaddr, 32 - X.Length + 1, X.Length);
            pubaddr[0] = 4;
        }

        public string OutputToValidPrivateKey(byte[] array)
        {
            byte[] rv = new byte[33];
            Array.Copy(privKey, 0, rv, 1, 32);
            rv[0] = 0x80;
            return ByteArrayToBase58Check(rv);
        }

        private string PrivateKeyBase58()
        {
            byte[] rv = new byte[33];
            Array.Copy(privKey, 0, rv, 1, 32);
            rv[0] = 0x80;
            return ByteArrayToBase58Check(rv);
        }

        private string ByteArrayToBase58Check(byte[] ba)
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

        public string FromByteArray(byte[] ba)
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

       

        private string GetAddressBase58()
        {
            byte[] _hash160 = ComputeHash160();

            byte[] hex2 = new byte[21];
            Array.Copy(_hash160, 0, hex2, 1, 20);
            hex2[0] = addressType;
            string _address = ByteArrayToBase58Check(hex2);
            return _address;
        }

        private byte[] ComputeHash160()
        {
            byte[] shaofpubkey = ComputeSha256(pubaddr);
            RIPEMD160 rip = System.Security.Cryptography.RIPEMD160.Create();
            return rip.ComputeHash(shaofpubkey);
        }
    }
}
