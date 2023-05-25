// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers.Binary;
using System.Diagnostics;

namespace System.Net.Sockets
{
    internal static class IPEndPointExtensions
    {
        // https://github.com/dotnet/runtime/issues/78993
        public static void Serialize(this IPEndPoint endPoint, Span<byte> destination)
        {
            SocketAddressPal.SetAddressFamily(destination, endPoint.AddressFamily);
            SocketAddressPal.SetPort(destination, (ushort)endPoint.Port);
            if (endPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Span<byte> addressBuffer = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                endPoint.Address.TryWriteBytes(addressBuffer, out _);
                SocketAddressPal.SetIPv6Address(destination, addressBuffer, (uint)endPoint.Address.ScopeId);
            }
            else
            {
#pragma warning disable CS0618
                SocketAddressPal.SetIPv4Address(destination, (uint)endPoint.Address.Address);
#pragma warning restore CS0618
            }
        }

        public static bool Equals(this IPEndPoint endPoint, ReadOnlySpan<byte> socketAddressBuffer)
        {
            if (endPoint.AddressFamily == SocketAddressPal.GetAddressFamily(socketAddressBuffer) &&
                endPoint.Port == (int)SocketAddressPal.GetPort(socketAddressBuffer))
            {
                if (endPoint.AddressFamily == AddressFamily.InterNetwork)
                {
#pragma warning disable CS0618
                    return endPoint.Address.Address == (long)SocketAddressPal.GetIPv4Address(socketAddressBuffer);
#pragma warning restore CS0618
                }
                else
                {
                    Span<byte> addressBuffer1 = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                    Span<byte> addressBuffer2 = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                    SocketAddressPal.GetIPv6Address(socketAddressBuffer, addressBuffer1, out uint scopeid);
                    endPoint.Address.TryWriteBytes(addressBuffer2, out _);
                    return endPoint.Address.ScopeId == (long)scopeid && addressBuffer1.SequenceEqual(addressBuffer2);
                }
            }

            return false;
        }

        /*
        public static Internals.SocketAddress Serialize(EndPoint endpoint)
        {
            Debug.Assert(!(endpoint is DnsEndPoint));

            var ipEndPoint = endpoint as IPEndPoint;
            if (ipEndPoint != null)
            {
                return new Internals.SocketAddress(ipEndPoint.Address, ipEndPoint.Port);
            }

            System.Net.SocketAddress address = endpoint.Serialize();
            return GetInternalSocketAddress(address);
        }

        public static EndPoint Create(this EndPoint thisObj, Internals.SocketAddress socketAddress)
        {
            AddressFamily family = socketAddress.Family;
            if (family != thisObj.AddressFamily)
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidAddressFamily, family.ToString(), thisObj.GetType().FullName, thisObj.AddressFamily.ToString()), nameof(socketAddress));
            }

            if (family == AddressFamily.InterNetwork || family == AddressFamily.InterNetworkV6)
            {
                if (socketAddress.Size < 8)
                {
                    throw new ArgumentException(SR.Format(SR.net_InvalidSocketAddressSize, socketAddress.GetType().FullName, thisObj.GetType().FullName), nameof(socketAddress));
                }

                return socketAddress.GetIPEndPoint();
            }
            else if (family == AddressFamily.Unknown)
            {
                return thisObj;
            }

            System.Net.SocketAddress address = GetNetSocketAddress(socketAddress);
            return thisObj.Create(address);
        }

        private static Internals.SocketAddress GetInternalSocketAddress(System.Net.SocketAddress address)
        {
            var result = new Internals.SocketAddress(address.Family, address.Size);
            for (int index = 0; index < address.Size; index++)
            {
                result[index] = address[index];
            }

            return result;
        }

        internal static System.Net.SocketAddress GetNetSocketAddress(Internals.SocketAddress address)
        {
            var result = new System.Net.SocketAddress(address.Family, address.Size);
            for (int index = 0; index < address.Size; index++)
            {
                result[index] = address[index];
            }

            return result;
        }
        */
    }
}
