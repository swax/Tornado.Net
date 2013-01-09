using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace Tornado
{
    public static class SocketExtensions
    {
        public static int fileno(this Socket sock)
        {
            return sock.Handle.ToInt64().GetHashCode();
        }

        static byte[] _recvBuff = new byte[] { };

        public static byte[] recv(this Socket sock, int amount)
        {
            //todo debug, make sure this is called just once, amount should be static chunk size
            if(_recvBuff.Length != amount)
                _recvBuff = new byte[amount];

            int read = sock.Receive(_recvBuff);
            if (read == 0)
                return null;

            return _recvBuff.substr(0, read);
        }
    }

    public static class DictionaryExtensions
    {
        public static TValue get<TKey, TValue>(this Dictionary<TKey, TValue> dict, TKey key, TValue defaultValue=default(TValue))
        {
            TValue value;

            if(dict.TryGetValue(key, out value))
                return value;

            return defaultValue;
        }

        public static TDefault get<TDefault>(this Dictionary<string, object> dict, string key, TDefault defaultValue = default(TDefault))
            where TDefault : class
        {
            object value;

            if (dict.TryGetValue(key, out value))
                return value as TDefault;

            return defaultValue;
        }

        public static void update<TKey, TValue>(this Dictionary<TKey, TValue> target, Dictionary<TKey, TValue> source)
        {
            foreach (var kvp in source)
                target[kvp.Key] = kvp.Value;
        }

        public static KeyValuePair<TKey, TValue> popitem<TKey, TValue>(this Dictionary<TKey, TValue> dict)
        {
            var popped = dict.First(); 
            dict.Remove(popped.Key);
            return popped;
        }
    }

    public static class LinkedListExtensions
    {
        public static T popleft<T>(this LinkedList<T> list)
        {
            T value = list.at(0);
            list.RemoveFirst();
            return value;
        }

        public static T at<T>(this LinkedList<T> list, int index)
        {
            int i = 0;
            foreach (var item in list)
            {
                if (i == index)
                    return item;
                else
                    i++;
            }

            throw new Exception("Index outside of bounds");
        }
    }

    public static class ByteArrayExtensions
    {
        public static byte[] substr(this byte[] self, int start, int length = -1)
        {
            if(length == -1)
                length = self.Length - start;

            byte[] result = new byte[length];

            Buffer.BlockCopy(self, start, result, 0, length);

            return result;
        }

        public static byte[] join(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        static readonly int[] Empty = new int[0];

        public static int find(this byte[] self, byte[] candidate)
        {
            if (IsEmptyLocate(self, candidate))
                return -1;

            for (int i = 0; i < self.Length; i++)
                if (IsMatch(self, i, candidate))
                    return i;

            return -1;
        }

        public static int[] Locate(this byte[] self, byte[] candidate)
        {
            if (IsEmptyLocate(self, candidate))
                return Empty;

            var list = new List<int>();

            for (int i = 0; i < self.Length; i++)
            {
                if (!IsMatch(self, i, candidate))
                    continue;

                list.Add(i);
            }

            return list.Count == 0 ? Empty : list.ToArray();
        }

        static bool IsMatch(byte[] array, int position, byte[] candidate)
        {
            if (candidate.Length > (array.Length - position))
                return false;

            for (int i = 0; i < candidate.Length; i++)
                if (array[position + i] != candidate[i])
                    return false;

            return true;
        }

        static bool IsEmptyLocate(byte[] array, byte[] candidate)
        {
            return array == null
                || candidate == null
                || array.Length == 0
                || candidate.Length == 0
                || candidate.Length > array.Length;
        }
    }

    public static class thread
    {
        public static int get_ident()
        {
            return System.Threading.Thread.CurrentThread.ManagedThreadId;
        }
    }

    public class TupleList<T1, T2> : List<Tuple<T1, T2>>
    {
        public void Add(T1 item, T2 item2)
        {
            Add(new Tuple<T1, T2>(item, item2));
        }
    }

    public class TupleList<T1, T2, T3> : List<Tuple<T1, T2, T3>>
    {
        public void Add(T1 item, T2 item2, T3 item3)
        {
            Add(new Tuple<T1, T2, T3>(item, item2, item3));
        }
    }

    public class TypeError : Exception
    {
        public TypeError(string message)
            : base(message)
        {
        }
    }

    public class RuntimeError : Exception
    {
        public RuntimeError(string message)
            : base(message)
        {
        }
    }

    public static class tornado
    {
        public static string version = "2.4.1";
    }

    public static class urlparse
    {
        public static string urljoin(string baseUrl, string relUrl)
        {
            return new Uri(new Uri(baseUrl), relUrl).ToString();
        }
    }
}
