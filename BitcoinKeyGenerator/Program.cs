using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using SLBitcoin;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Threading;
using System.Collections.Concurrent;

namespace BitcoinKeyGenerator
{
    class Program
    {
        private static ConcurrentQueue<KeyPair> kp = new ConcurrentQueue<KeyPair>();
        private static int y = 0;
        static void Main(string[] args)
        {


            for (int i = 0; i < 50; i++)
            {
                CKeys();
                y = 0;
            }

            Console.ReadKey();
        }

        private static void GenKey(object a)
        {
            kp.Enqueue(DeepCopy(BtcAG.CreateKeys()));
        }

        private static T DeepCopy<T>(T item)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            MemoryStream stream = new MemoryStream();
            formatter.Serialize(stream, item);
            stream.Seek(0, SeekOrigin.Begin);
            T result = (T)formatter.Deserialize(stream);
            stream.Close();
            return result;
        }

        private static void WriteConsole(object a)
        {
            KeyPair k = null;

            if (kp.TryDequeue(out k))
            {
                Console.WriteLine(string.Format("Private Key: {0}, Public Address: {1}", k.strPrivateKey, k.strPublicAddress));

                y++;
            }
        }

        private static void CKeys()
        {
            int x = 0;
            while (x < 100)
            {
                ThreadPool.QueueUserWorkItem(new WaitCallback(GenKey), null);

                x++;
            }

            while (y < 100)
            {
                if (!kp.IsEmpty)
                    ThreadPool.QueueUserWorkItem(new WaitCallback(WriteConsole), null);
            }
        }
    }

    public class ThreadInfo
    {
        public string PrivateKey { get; set; }
        public string PublicAddress { get; set; }
    }
}
