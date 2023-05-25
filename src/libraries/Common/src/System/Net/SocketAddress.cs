// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.Diagnostics;
//using System.Globalization;
using System.Net.Sockets;
//using System.Text;

#if SYSTEM_NET_PRIMITIVES_DLL
namespace System.Net
#else
namespace System.Net.Internals.old
#endif
{
    // This class is used when subclassing EndPoint, and provides indication
    // on how to format the memory buffers that the platform uses for network addresses.
#if SYSTEM_NET_PRIMITIVES_DLL
    public
#else
    internal sealed
#endif
    class SocketAddress
    {
#pragma warning disable CA1802 // these could be const on Windows but need to be static readonly for Unix
        internal static readonly int IPv6AddressSize = SocketAddressPal.IPv6AddressSize;
        internal static readonly int IPv4AddressSize = SocketAddressPal.IPv4AddressSize;
        internal static readonly int UdsAddressSize = 128;
        internal static readonly int MaxAddressSize = 128;
#pragma warning restore CA1802

        internal int InternalSize;
        //internal byte[] InternalBuffer;
        private Memory<byte> InternalBuffer;
        // Pinning?
        //public byte[] Buffer;

        private const int MinSize = 2;
        //private const int MaxSize = 32; // IrDA requires 32 bytes
        private const int DataOffset = 2;
        private bool _changed = true;
        private int _hash;

        public AddressFamily Family
        {
            get
            {
                return SocketAddressPal.GetAddressFamily(InternalBuffer.Span);
            }
        }

        public int Size
        {
            get
            {
                return InternalSize;
            }
            set
            {
                if (value >= InternalBuffer.Length)
                {
                    throw new ArgumentException("BOO");
                }
                InternalSize = value;
            }
        }

        // Access to unmanaged serialized data. This doesn't
        // allow access to the first 2 bytes of unmanaged memory
        // that are supposed to contain the address family which
        // is readonly.
        public byte this[int offset]
        {
            get
            {
                //Console.WriteLine("setting byts {0} from {1} {2}", offset, Size, Buffer.Length);
                if (offset < 0 || offset >= Size)
                //if (offset < 0 || offset >= Buffer.Length)
                {
                    throw new IndexOutOfRangeException();
                }
                return InternalBuffer.Span[offset];
            }
            set
            {
                //Console.WriteLine("setting byts {0} from {1} {2}", offset, Size, Buffer.Length);
                //if (offset < 0 || offset >= Size)
                if (offset < 0 || offset >= InternalBuffer.Length)
                {
                    throw new IndexOutOfRangeException();
                }
                if (InternalBuffer.Span[offset] != value)
                {
                //    _changed = true;
                }
                InternalBuffer.Span[offset] = value;
            }
        }

        public Memory<byte> SocketBuffer
        {
            get
            {
                return InternalBuffer.Slice(0, InternalSize);
            }
            set
            {
                InternalBuffer = value;
            }
        }

        public bool TryGetAddress(out Int128 address, out long scopeid)
        {
            if (Family == AddressFamily.InterNetwork)
            {
                Debug.Assert(Size >= IPv4AddressSize);

                address = SocketAddressPal.GetIPv4Address(InternalBuffer.Span) & 0x0FFFFFFFF;
                scopeid = 0;
                return true;
            }
            else if (Family == AddressFamily.InterNetworkV6)
            {
                Span<byte> addressBuffer = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                uint scope;
                SocketAddressPal.GetIPv6Address(InternalBuffer.Span, addressBuffer, out scope);
                //address = 0;
                //Int128.P
                address = BinaryPrimitives.ReadInt128LittleEndian(addressBuffer);
                scopeid = (long)scope;
                return true;
            }

            address = 0;
            scopeid = 0;
            return false;
        }

        public bool TryGetPort(out int port)
        {
            if (Family == AddressFamily.InterNetwork || Family == AddressFamily.InterNetworkV6)
            {
                port = (int)SocketAddressPal.GetPort(InternalBuffer.Span);
                return true;
            }

            port = 0;
            return false;
        }

        public bool TryWriteAddressBytes(Span<byte> destination, out int bytesWritten)
        {

            if (Family == AddressFamily.InterNetworkV6)
            {
                //uint scope;
                SocketAddressPal.GetIPv6Address(InternalBuffer.Span, destination, out _);
                bytesWritten = IPAddressParserStatics.IPv6AddressBytes;
                return true;


            }
            else if (Family == AddressFamily.InterNetwork)
            {
                uint address = SocketAddressPal.GetIPv4Address(InternalBuffer.Span) & 0x0FFFFFFFF;
                BinaryPrimitives.WriteUInt32LittleEndian(destination, address);
                bytesWritten = 4;
                return true;
            }

            bytesWritten = 0;
            return false;
        }
        //GetPort() => (int)SocketAddressPal.GetPort(Buffer);

        private static int GetMaxAddresFamilySize(AddressFamily family) => family switch
        {
            AddressFamily.InterNetwork => IPv4AddressSize,
            AddressFamily.InterNetworkV6 => IPv6AddressSize,
            AddressFamily.Unix => UdsAddressSize,
            _ => MaxAddressSize
        };

        public SocketAddress(AddressFamily family) : this(family, GetMaxAddresFamilySize(family))
        {
        }

        public SocketAddress(AddressFamily family, int size)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(size, MinSize);

            InternalSize = size;
//#if !SYSTEM_NET_PRIMITIVES_DLL && WINDOWS
#if WINDOWS
            // WSARecvFrom needs a pinned pointer to the 32bit socket address size: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecvfrom
            // Allocate IntPtr.Size extra bytes at the end of Buffer ensuring IntPtr.Size alignment, so we don't need to pin anything else.
            // The following formula will extend 'size' to the alignment boundary then add IntPtr.Size more bytes.
            size = (size + IntPtr.Size - 1) / IntPtr.Size * IntPtr.Size + IntPtr.Size;
#endif
            InternalBuffer = new byte[size];

            SocketAddressPal.SetAddressFamily(InternalBuffer.Span, family);
        }

        internal SocketAddress(IPAddress ipAddress)
            : this(ipAddress.AddressFamily,
                ((ipAddress.AddressFamily == AddressFamily.InterNetwork) ? IPv4AddressSize : IPv6AddressSize))
        {
            // No Port.
            SocketAddressPal.SetPort(InternalBuffer.Span, 0);

            if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Span<byte> addressBytes = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                ipAddress.TryWriteBytes(addressBytes, out int bytesWritten);
                Debug.Assert(bytesWritten == IPAddressParserStatics.IPv6AddressBytes);

                SocketAddressPal.SetIPv6Address(InternalBuffer.Span, addressBytes, (uint)ipAddress.ScopeId);
            }
            else
            {
#pragma warning disable CS0618 // using Obsolete Address API because it's the more efficient option in this case
                uint address = unchecked((uint)ipAddress.Address);
#pragma warning restore CS0618

                Debug.Assert(ipAddress.AddressFamily == AddressFamily.InterNetwork);
                SocketAddressPal.SetIPv4Address(InternalBuffer.Span, address);
            }
        }

        internal SocketAddress(IPAddress ipaddress, int port)
            : this(ipaddress)
        {
            SocketAddressPal.SetPort(InternalBuffer.Span, unchecked((ushort)port));
        }

        internal SocketAddress(AddressFamily addressFamily, ReadOnlySpan<byte> buffer)
        {
            InternalBuffer = buffer.ToArray();
            InternalSize = buffer.Length;
            SocketAddressPal.SetAddressFamily(InternalBuffer.Span, addressFamily);
        }

        internal IPAddress GetIPAddress()
        {
            if (Family == AddressFamily.InterNetworkV6)
            {
                Debug.Assert(Size >= IPv6AddressSize);

                Span<byte> address = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                uint scope;
                SocketAddressPal.GetIPv6Address(InternalBuffer.Span, address, out scope);
                return new IPAddress(address, (long)scope);
            }
            else if (Family == AddressFamily.InterNetwork)
            {
                Debug.Assert(Size >= IPv4AddressSize);
                long address = (long)SocketAddressPal.GetIPv4Address(InternalBuffer.Span) & 0x0FFFFFFFF;
                return new IPAddress(address);
            }
            else
            {
#if SYSTEM_NET_PRIMITIVES_DLL
                throw new SocketException(SocketError.AddressFamilyNotSupported);
#else
                throw new SocketException((int)SocketError.AddressFamilyNotSupported);
#endif
            }
        }

        internal int GetPort() => (int)SocketAddressPal.GetPort(InternalBuffer.Span);

        internal IPEndPoint GetIPEndPoint()
        {
            return new IPEndPoint(GetIPAddress(), GetPort());
        }

#if !SYSTEM_NET_PRIMITIVES_DLL && WINDOWS
        // For ReceiveFrom we need to pin address size, using reserved Buffer space.
        internal void CopyAddressSizeIntoBuffer()
        {
            int addressSizeOffset = GetAddressSizeOffset();
            InternalBuffer[addressSizeOffset] = unchecked((byte)(InternalSize));
            InternalBuffer[addressSizeOffset + 1] = unchecked((byte)(InternalSize >> 8));
            InternalBuffer[addressSizeOffset + 2] = unchecked((byte)(InternalSize >> 16));
            InternalBuffer[addressSizeOffset + 3] = unchecked((byte)(InternalSize >> 24));
        }

        // Can be called after the above method did work.
        internal int GetAddressSizeOffset()
        {
            return InternalBuffer.Length - IntPtr.Size;
        }
#endif

        public override bool Equals(object? comparand) =>
            comparand is SocketAddress other &&
            InternalBuffer.Span.Slice(0, Size).SequenceEqual(other.InternalBuffer.Span.Slice(0, other.Size));

        public bool Equals(EndPoint comparand)
        {
            if (comparand == null)
            {
                return false;
            }

            IPEndPoint? ipe = comparand as IPEndPoint;
            if (ipe != null)
            {
                if (GetPort() != ipe.Port)
                {
                    return false;
                }
                if (Family == AddressFamily.InterNetwork)
                {
#pragma warning disable CS0618 // using Obsolete Address API because it's the more efficient option in this case
                    return ipe.Address.Address == (long)(SocketAddressPal.GetIPv4Address(InternalBuffer.Span) & 0x0FFFFFFFF);
#pragma warning restore CS0618
                }

                Span<byte> addressBytes = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                ipe.Address.TryWriteBytes(addressBytes, out int bytesWritten);
                Debug.Assert(bytesWritten == IPAddressParserStatics.IPv6AddressBytes);

                // TODO find address bytes in buffer?
                Span<byte> addressBytes2 = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                uint scope;
                SocketAddressPal.GetIPv6Address(InternalBuffer.Span, addressBytes2, out scope);
                return addressBytes.SequenceEqual(addressBytes2);
            }
            else if (Family != comparand.AddressFamily)
            {
                return false;
            }
            else
            {
#if SYSTEM_NET_PRIMITIVES_DLL
                SocketAddress socketAddress = comparand.Serialize();
                return socketAddress.InternalBuffer.Span.SequenceEqual(InternalBuffer!.Span.Slice(0, Size));
#else
            // TODO delete.
            return false;
#endif
            }
        }

        public override int GetHashCode()
        {
            if (_changed)
            {
                _changed = false;
                _hash = 0;

                int i;
                int size = Size & ~3;

                for (i = 0; i < size; i += 4)
                {
                    _hash ^= BinaryPrimitives.ReadInt32LittleEndian(InternalBuffer.Span.Slice(i));
                }
                if ((Size & 3) != 0)
                {
                    int remnant = 0;
                    int shift = 0;

                    for (; i < Size; ++i)
                    {
                        remnant |= ((int)InternalBuffer.Span[i]) << shift;
                        shift += 8;
                    }
                    _hash ^= remnant;
                }
            }
            return _hash;
        }

        public override string ToString()
        {
            // Get the address family string.  In almost all cases, this should be a cached string
            // from the enum and won't actually allocate.
            string familyString = Family.ToString();

            // Determine the maximum length needed to format.
            int maxLength =
                familyString.Length + // AddressFamily
                1 + // :
                10 + // Size (max length for a positive Int32)
                2 + // :{
                (Size - DataOffset) * 4 + // at most ','+3digits per byte
                1; // }

            Span<char> result = maxLength <= 256 ? // arbitrary limit that should be large enough for the vast majority of cases
                stackalloc char[256] :
                new char[maxLength];

            familyString.CopyTo(result);
            int length = familyString.Length;

            result[length++] = ':';

            bool formatted = Size.TryFormat(result.Slice(length), out int charsWritten);
            Debug.Assert(formatted);
            length += charsWritten;

            result[length++] = ':';
            result[length++] = '{';

            //byte[] buffer = InternalBuffer;
            for (int i = DataOffset; i < Size; i++)
            {
                if (i > DataOffset)
                {
                    result[length++] = ',';
                }

                formatted = InternalBuffer.Span[i].TryFormat(result.Slice(length), out charsWritten);
                Debug.Assert(formatted);
                length += charsWritten;
            }

            result[length++] = '}';
            return result.Slice(0, length).ToString();
        }
    }
}
