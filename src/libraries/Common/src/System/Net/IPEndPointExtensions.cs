// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net;

namespace System.Net.Sockets
{
    internal static class IPEndPointExtensions
    {
        public static IPAddress GetIPAddress(ReadOnlySpan<byte> socketAddressBuffer)
        {
            if (SocketAddressPal.GetAddressFamily(socketAddressBuffer) == AddressFamily.InterNetworkV6)
            {
                Span<byte> address = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                uint scope;
                SocketAddressPal.GetIPv6Address(socketAddressBuffer, address, out scope);
                return new IPAddress(address, (long)scope);
            }

            return new IPAddress((long)SocketAddressPal.GetIPv4Address(socketAddressBuffer) & 0x0FFFFFFFF);
        }

        public static void SetIPAddress(Span<byte> socketAddressBuffer, IPAddress address)
        {
            SocketAddressPal.SetAddressFamily(socketAddressBuffer, address.AddressFamily);
            SocketAddressPal.SetPort(socketAddressBuffer, 0);
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
#pragma warning disable CS0618
                SocketAddressPal.SetIPv4Address(socketAddressBuffer, (uint)address.Address);
#pragma warning restore CS0618
            }
            else
            {
                Span<byte> addressBuffer = stackalloc byte[IPAddressParserStatics.IPv6AddressBytes];
                address.TryWriteBytes(addressBuffer, out _);
                SocketAddressPal.SetIPv6Address(socketAddressBuffer, addressBuffer, (uint)address.ScopeId);
            }
        }

        public static IPEndPoint CreateIPEndPoint(ReadOnlySpan<byte> socketAddressBuffer)
        {
           return new IPEndPoint(GetIPAddress(socketAddressBuffer), SocketAddressPal.GetPort(socketAddressBuffer));
        }

        // https://github.com/dotnet/runtime/issues/78993
        public static void Serialize(this IPEndPoint endPoint, Span<byte> destination)
        {
            SocketAddressPal.SetAddressFamily(destination, endPoint.AddressFamily);
            SetIPAddress(destination, endPoint.Address);
            SocketAddressPal.SetPort(destination, (ushort)endPoint.Port);
        }
    }
}
