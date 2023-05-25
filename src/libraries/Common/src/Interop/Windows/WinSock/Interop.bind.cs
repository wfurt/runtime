// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;
using System.Net.Sockets;
using System;

internal static partial class Interop
{
    internal static partial class Winsock
    {
        [LibraryImport(Interop.Libraries.Ws2_32, SetLastError = true)]
        internal static partial SocketError bind(
            SafeSocketHandle socketHandle,
            byte[] socketAddress,
            int socketAddressSize);

        [LibraryImport(Interop.Libraries.Ws2_32, SetLastError = true)]
        internal static unsafe partial SocketError bind(
            SafeSocketHandle socketHandle,
            byte* socketAddress,
            int socketAddressSize);

        internal static unsafe SocketError bind(
            SafeSocketHandle socketHandle,
            ReadOnlySpan<byte> socketAddress)
        {
            fixed (byte* ptr = &MemoryMarshal.GetReference(socketAddress))
            {
                return bind(socketHandle, ptr, socketAddress.Length);
            }
        }
    }
}
