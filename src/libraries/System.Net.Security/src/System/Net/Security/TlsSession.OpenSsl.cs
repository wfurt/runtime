// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Sockets;

namespace System.Net.Security
{
    public sealed partial class TlsSession
    {
        // Native socket binding (SSL_set_fd fast path) is not enabled on this
        // servicing branch. All I/O flows through the managed buffered path
        // (ProcessHandshake/Encrypt/Decrypt over SslStreamPal).
#pragma warning disable CA1822 // partial method on instance type; cannot be static
        partial void EnableNativeSocketBinding(SafeSocketHandle socket, ref bool nativeBindingEnabled)
        {
            // Intentionally leave nativeBindingEnabled = false.
        }
#pragma warning restore CA1822
    }
}
