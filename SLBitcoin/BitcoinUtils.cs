using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
//using SLModels;
using NBitcoin;

namespace SLBitcoin
{
    public class BitcoinUtils
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int memcmp(byte[] b1, byte[] b2, long count);
        private static string Base58characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        public struct Report
        {
            public bool _matchFound;
            public double _percentageOfMatches;
            public int[] _indexOfMatches;
        }

        public BitcoinUtils()
        {
        }

        public Report CompareBitcoinAddresses(List<KeyPair> _input, List<KeyPair> _output)
        {
            Report _report = new Report();
            int _matchedCount = 0;

            for (int i = 0; i < _input.Count; i++)
            {
                if (ByteArrayCompare(_input.ElementAt(i).bytePrivateKey, _output.ElementAt(i).bytePrivateKey))
                {
                    _report._matchFound = true;
                    _matchedCount++;
                }
            }

            if (_report._matchFound == true)
            {
                _report._indexOfMatches = new int[_matchedCount];
                int _index = 0;
                _report._percentageOfMatches = (_matchedCount / _input.Count) * 100;

                for (int i = 0; i < _input.Count; i++)
                {
                    if (ByteArrayCompare(_input.ElementAt(i).bytePrivateKey, _output.ElementAt(i).bytePrivateKey))
                        _report._indexOfMatches[_index++] = i;
                }
            }

            return _report;
        }

        public static bool ByteArrayCompare(byte[] b1, byte[] b2)
        {
            return b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;
        }

        /*
        public static bool ValidatePrivateKey(string privateKey, string pubAddress)
        {
            try
            {
                BitcoinSecret paymentSecret = Key.Parse(privateKey).GetBitcoinSecret(Network.Main);

                string msg = "Test Sig";
                string sig = paymentSecret.PrivateKey.SignMessage(msg);

                if (paymentSecret.GetAddress().VerifyMessage(msg, sig))
                    return new BitcoinPubKeyAddress(pubAddress).VerifyMessage(msg, sig);
                else
                    return false;

            }
            catch
            {
                return false;
            }
        }
        */


        public static bool B58Decode(string source, ref byte[] destination)
        {
            int i = 0;
            while (i < source.Length)
            {
                if (source[i] == 0 || !Char.IsWhiteSpace(source[i]))
                {
                    break;
                }
                i++;
            }
            int zeros = 0;
            while (source[i] == '1')
            {
                zeros++;
                i++;
            }
            byte[] b256 = new byte[(source.Length - i) * 733 / 1000 + 1];
            while (i < source.Length && !Char.IsWhiteSpace(source[i]))
            {
                int ch = Base58characters.IndexOf(source[i]);
                if (ch == -1) //null
                {
                    return false;
                }
                int carry = Base58characters.IndexOf(source[i]);
                for (int k = b256.Length - 1; k >= 0; k--)
                {
                    carry += 58 * b256[k];
                    b256[k] = (byte)(carry % 256);
                    carry /= 256;
                }
                i++;
            }
            while (i < source.Length && Char.IsWhiteSpace(source[i]))
            {
                i++;
            }
            if (i != source.Length)
            {
                return false;
            }
            int j = 0;
            while (j < b256.Length && b256[j] == 0)
            {
                j++;
            }
            destination = new byte[zeros + (b256.Length - j)];
            for (int kk = 0; kk < destination.Length; kk++)
            {
                if (kk < zeros)
                {
                    destination[kk] = 0x00;
                }
                else
                {
                    destination[kk] = b256[j++];
                }
            }
            return true;
        }

        public static string ByteArrayToHexString(byte[] source)
        {
            return BitConverter.ToString(source).Replace("-", "");
        }
    }
}
