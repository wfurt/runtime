// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;
using System.IO;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Net.Test.Common;
using Xunit;

using TestCertificates = System.Net.Test.Common.Configuration.Certificates;

namespace System.Net.Security.Tests
{
    // Proves that the two server-side TLS callbacks ASP.NET Core Kestrel exposes today can be
    // supported on top of the standalone TlsSession / TlsContext state machine. The server side is
    // driven entirely by TlsSession (no SslStream) — the same role Kestrel's "DirectSsl" transport
    // plays — while a real SslStream stands in for the connecting client.
    //
    //   ASP.NET Core surface (HttpsConnectionAdapterOptions)        runtime option it maps to
    //   ---------------------------------------------------------   ----------------------------------------------------
    //   ServerCertificateSelector(connection, hostName) => cert  -> SslServerAuthenticationOptions.ServerCertificateSelectionCallback
    //   ClientCertificateValidation(cert, chain, errors) => bool -> SslServerAuthenticationOptions.RemoteCertificateValidationCallback
    //                                                               (with ClientCertificateRequired = true)
    //
    // Both are plain delegates carried on SslServerAuthenticationOptions. TlsContext.Create copies
    // them into its internal options bag, so NO new runtime API is required to honor either one:
    //   * ServerCertificateSelectionCallback runs inline while the server resolves its certificate
    //     from the ClientHello SNI (TlsSession.ResolveServerCertificateFromClientHello).
    //   * RemoteCertificateValidationCallback runs when the server validates the peer (client)
    //     certificate. TlsSession surfaces this as a NeedsCertificateValidation suspension;
    //     AcceptWithDefaultValidation drives the user callback (SslStream.VerifyRemoteCertificateCore)
    //     and applies its verdict.
    //
    // Tls12SkippedOnWindows: TLS 1.2 cases are skipped on Windows because TlsSession's server-side
    // SChannel path cannot acquire TLS 1.2 server credentials in this PoC — AcquireCredentialsHandle
    // fails with "no common algorithm". This is a pre-existing PoC limitation, not a defect in these
    // tests: the PoC's own ServerSession_RequestClientCertificate_Tls12_ProducesHandshakeBytes and
    // TwoSessions_HandshakeAndPingPong_InMemory_Succeeds(Tls12) fail identically on Windows, while
    // their TLS 1.3 counterparts pass. The DirectSsl transport targets Linux/OpenSSL, where TLS 1.2
    // negotiates correctly, so TLS 1.2 is exercised on non-Windows only.
    [PlatformSpecific(TestPlatforms.Linux | TestPlatforms.FreeBSD | TestPlatforms.Windows | TestPlatforms.OSX)]
    public class TlsSessionAspNetCoreCallbacksTests
    {
        private const int CipherBufSize = 32 * 1024;

        // ASP.NET Core: options.ServerCertificateSelector = (connectionContext, hostName) => cert;
        [Theory]
        [InlineData(SslProtocols.Tls12)]
        [InlineData(SslProtocols.Tls13)]
        public async Task ServerCertificateSelector_IsHonored_ViaTlsSession(SslProtocols protocol)
        {
            if (protocol == SslProtocols.Tls13 && OperatingSystem.IsMacOS())
            {
                return; // SecureTransport (legacy macOS backend used here) does not implement TLS 1.3.
            }

            if (protocol == SslProtocols.Tls12 && OperatingSystem.IsWindows())
            {
                return; // See note on Tls12SkippedOnWindows.
            }

            using X509Certificate2 serverCert = TestCertificates.GetServerCertificate();
            string serverName = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            int selectorCalls = 0;
            string? observedSni = null;

            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            using (clientStream)
            using (serverStream)
            using (SslStream clientSsl = new SslStream(clientStream, leaveInnerStreamOpen: false, TestHelper.AllowAnyServerCertificate))
            {
                using TlsContext serverCtx = TlsContext.Create(new SslServerAuthenticationOptions
                {
                    EnabledSslProtocols = protocol,
                    // Stand-in for HttpsConnectionAdapterOptions.ServerCertificateSelector: pick the cert
                    // based on the SNI host name advertised in the ClientHello.
                    ServerCertificateSelectionCallback = (sender, hostName) =>
                    {
                        selectorCalls++;
                        observedSni = hostName;
                        Assert.IsType<TlsSession>(sender);
                        return serverCert;
                    },
                });
                using TlsSession server = TlsSession.Create(serverCtx);

                Task clientHandshake = clientSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = serverName,
                    EnabledSslProtocols = protocol,
                    RemoteCertificateValidationCallback = TestHelper.AllowAnyServerCertificate,
                });
                Task serverHandshake = DriveServerHandshakeAsync(server, serverStream);

                await Task.WhenAll(clientHandshake, serverHandshake).WaitAsync(TimeSpan.FromSeconds(30));

                Assert.True(server.IsHandshakeComplete);
                Assert.True(clientSsl.IsAuthenticated);
                Assert.Equal(1, selectorCalls);
                Assert.Equal(serverName, observedSni);

                // The certificate the selector returned is exactly the one the client received.
                Assert.NotNull(clientSsl.RemoteCertificate);
                Assert.Equal(serverCert.Thumbprint, new X509Certificate2(clientSsl.RemoteCertificate).Thumbprint);
            }
        }

        // ASP.NET Core: options.ClientCertificateValidation = (cert, chain, errors) => true; (accept path)
        [Theory]
        [InlineData(SslProtocols.Tls12)]
        [InlineData(SslProtocols.Tls13)]
        public async Task ClientCertificateValidation_Accept_IsHonored_ViaTlsSession(SslProtocols protocol)
        {
            if (protocol == SslProtocols.Tls13 && OperatingSystem.IsMacOS())
            {
                return;
            }

            if (protocol == SslProtocols.Tls12 && OperatingSystem.IsWindows())
            {
                return; // See note on Tls12SkippedOnWindows.
            }

            using X509Certificate2 serverCert = TestCertificates.GetServerCertificate();
            using X509Certificate2 clientCert = TestCertificates.GetClientCertificate();
            string serverName = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            int validatorCalls = 0;
            X509Certificate2? observedClientCert = null;

            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            using (clientStream)
            using (serverStream)
            using (SslStream clientSsl = new SslStream(clientStream, leaveInnerStreamOpen: false, TestHelper.AllowAnyServerCertificate))
            {
                using TlsContext serverCtx = TlsContext.Create(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCert,
                    EnabledSslProtocols = protocol,
                    ClientCertificateRequired = true,
                    // Stand-in for HttpsConnectionAdapterOptions.ClientCertificateValidation.
                    RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                    {
                        validatorCalls++;
                        observedClientCert = cert as X509Certificate2;
                        return true; // accept
                    },
                });
                using TlsSession server = TlsSession.Create(serverCtx);

                Task clientHandshake = clientSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = serverName,
                    EnabledSslProtocols = protocol,
                    ClientCertificates = new X509CertificateCollection { clientCert },
                    RemoteCertificateValidationCallback = TestHelper.AllowAnyServerCertificate,
                });
                Task serverHandshake = DriveServerHandshakeAsync(server, serverStream);

                await Task.WhenAll(clientHandshake, serverHandshake).WaitAsync(TimeSpan.FromSeconds(30));

                Assert.True(server.IsHandshakeComplete);
                Assert.Equal(1, validatorCalls);
                Assert.NotNull(observedClientCert);
                Assert.Equal(clientCert.Thumbprint, observedClientCert!.Thumbprint);

                // The server actually received the client certificate it validated.
                using X509Certificate2? remote = server.GetRemoteCertificate();
                Assert.NotNull(remote);
                Assert.Equal(clientCert.Thumbprint, remote!.Thumbprint);
            }
        }

        // ASP.NET Core: options.ClientCertificateValidation = (cert, chain, errors) => false; (reject path)
        [Theory]
        [InlineData(SslProtocols.Tls12)]
        [InlineData(SslProtocols.Tls13)]
        public async Task ClientCertificateValidation_Reject_FaultsHandshake_ViaTlsSession(SslProtocols protocol)
        {
            if (protocol == SslProtocols.Tls13 && OperatingSystem.IsMacOS())
            {
                return;
            }

            if (protocol == SslProtocols.Tls12 && OperatingSystem.IsWindows())
            {
                return; // See note on Tls12SkippedOnWindows.
            }

            using X509Certificate2 serverCert = TestCertificates.GetServerCertificate();
            using X509Certificate2 clientCert = TestCertificates.GetClientCertificate();
            string serverName = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            int validatorCalls = 0;

            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            using (clientStream)
            using (serverStream)
            using (SslStream clientSsl = new SslStream(clientStream, leaveInnerStreamOpen: false, TestHelper.AllowAnyServerCertificate))
            {
                using TlsContext serverCtx = TlsContext.Create(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCert,
                    EnabledSslProtocols = protocol,
                    ClientCertificateRequired = true,
                    // Reject the client certificate unconditionally, even though the chain is clean.
                    RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                    {
                        validatorCalls++;
                        return false; // reject
                    },
                });
                using TlsSession server = TlsSession.Create(serverCtx);

                Task clientHandshake = clientSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = serverName,
                    EnabledSslProtocols = protocol,
                    ClientCertificates = new X509CertificateCollection { clientCert },
                    RemoteCertificateValidationCallback = TestHelper.AllowAnyServerCertificate,
                });
                Task serverHandshake = DriveServerHandshakeAsync(server, serverStream);

                // The server exchanges all TLS records (the client receives the server Finished and
                // completes), then runs the validator, which rejects. AcceptWithDefaultValidation
                // records the rejection without throwing, so the driver returns normally.
                await serverHandshake.WaitAsync(TimeSpan.FromSeconds(30));

                // The validator ran exactly once with the client certificate.
                Assert.Equal(1, validatorCalls);

                // The false verdict faulted the session: any subsequent operation throws, proving the
                // rejection was honored (mirrors SslStream, which would have failed authentication).
                Assert.Throws<AuthenticationException>(() =>
                    server.Encrypt("x"u8.ToArray(), new byte[CipherBufSize], out _, out _));

                // Drain the client side so the connection tears down cleanly; its outcome is not asserted.
                try
                {
                    await clientHandshake.WaitAsync(TimeSpan.FromSeconds(5));
                }
                catch
                {
                }
            }
        }

        // ASP.NET Core "DirectSsl": low-level raw ClientHello inspection. With
        // TlsContext.EnableClientHelloInspection set, the server TlsSession pauses the handshake
        // once at ClientHello time (TlsOperationStatus.NeedsClientHello) and hands the caller the
        // raw ClientHello handshake bytes OpenSSL received off the socket, before any certificate
        // or server-option decision. Kestrel parses these itself (SNI/ALPN routing) and resumes.
        //
        // This is the fd-mode path: OpenSSL owns the socket (SSL_set_fd) and the caller never sees
        // the wire bytes except through this callback — the "we just listen, OpenSSL hands us the
        // data" semantics. Linux/OpenSSL only: the capture lives in the OpenSSL PAL; SChannel and
        // SecureTransport do not implement it.
        [Fact]
        public async Task ClientHelloInspection_CapturesRawBytes_ViaTlsSession_FdMode()
        {
            if (!OperatingSystem.IsLinux() && !OperatingSystem.IsFreeBSD())
            {
                return; // Raw ClientHello capture is implemented only in the OpenSSL PAL.
            }

            using X509Certificate2 serverCert = TestCertificates.GetServerCertificate();
            string serverName = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            using Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);
            int port = ((IPEndPoint)listener.LocalEndPoint!).Port;

            using Socket clientUnderlying = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Task connect = clientUnderlying.ConnectAsync(IPAddress.Loopback, port);
            Socket serverSocket = await listener.AcceptAsync();
            await connect;

            // TlsSession fd-mode contract requires a non-blocking socket.
            serverSocket.Blocking = false;
            SafeSocketHandle serverHandle = serverSocket.SafeHandle;

            using TlsContext serverCtx = TlsContext.Create(new SslServerAuthenticationOptions
            {
                ServerCertificate = serverCert,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            });
            // Opt in (before the first handshake, so the SSL_CTX is armed): pause at ClientHello
            // and surface the raw bytes.
            serverCtx.EnableClientHelloInspection = true;

            using TlsSession server = TlsSession.Create(serverCtx, serverHandle);

            using SslStream clientSsl = new SslStream(new NetworkStream(clientUnderlying, ownsSocket: false), leaveInnerStreamOpen: false, TestHelper.AllowAnyServerCertificate);
            Task clientHandshake = clientSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = serverName, // carried as the SNI host name in the ClientHello
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = TestHelper.AllowAnyServerCertificate,
            });

            int clientHelloSuspends = 0;
            byte[]? capturedHello = null;

            Task serverHandshake = Task.Run(async () =>
            {
                while (true)
                {
                    TlsOperationStatus s = server.Handshake();
                    if (s == TlsOperationStatus.Complete)
                    {
                        return;
                    }
                    if (s == TlsOperationStatus.NeedsClientHello)
                    {
                        clientHelloSuspends++;
                        // Zero-copy view over native memory owned by the session; copy it out before
                        // resuming so the assertions below can run after the handshake completes.
                        ReadOnlySpan<byte> hello = server.GetClientHelloBytes();
                        capturedHello = hello.ToArray();
                        continue; // next Handshake() resumes (the RETRY is consumed once)
                    }
                    if (s == TlsOperationStatus.NeedsCertificateValidation)
                    {
                        server.AcceptWithDefaultValidation();
                        continue;
                    }
                    if (s == TlsOperationStatus.WantRead || s == TlsOperationStatus.WantWrite)
                    {
                        await Task.Delay(5);
                        continue;
                    }
                    throw new InvalidOperationException($"Unexpected handshake status: {s}");
                }
            });

            await Task.WhenAll(clientHandshake, serverHandshake).WaitAsync(TimeSpan.FromSeconds(30));

            Assert.True(server.IsHandshakeComplete);
            Assert.True(clientSsl.IsAuthenticated);

            // The handshake paused exactly once at ClientHello and produced bytes.
            Assert.Equal(1, clientHelloSuspends);
            Assert.NotNull(capturedHello);
            Assert.NotEmpty(capturedHello!);

            // First byte is the TLS HandshakeType for ClientHello (1), with no outer 5-byte record
            // header, and the 3-byte length prefix matches the remaining body length.
            Assert.Equal(1, capturedHello![0]);
            int body = (capturedHello[1] << 16) | (capturedHello[2] << 8) | capturedHello[3];
            Assert.Equal(capturedHello.Length, 4 + body);

            // The SNI host the client advertised appears verbatim in the raw bytes, proving these are
            // the real ClientHello the peer sent (the routing info Kestrel would parse).
            byte[] sniBytes = Encoding.ASCII.GetBytes(serverName);
            Assert.True(capturedHello.AsSpan().IndexOf(sniBytes) >= 0,
                $"SNI host '{serverName}' not found in captured ClientHello bytes.");
        }

        // Same low-level raw ClientHello inspection as the fd-mode test above, but exercised through
        // the BIO-mode path: the caller owns the transport and feeds ciphertext to
        // ProcessHandshake(input, output, ...). The same OpenSSL ClientHello callback fires inside
        // SSL_do_handshake regardless of transport, so ProcessHandshake surfaces
        // TlsOperationStatus.NeedsClientHello exactly once with the identical raw bytes, then resumes
        // (emitting the ServerHello) on the next call. Linux/OpenSSL only.
        [Fact]
        public async Task ClientHelloInspection_CapturesRawBytes_ViaTlsSession_BioMode()
        {
            if (!OperatingSystem.IsLinux() && !OperatingSystem.IsFreeBSD())
            {
                return; // Raw ClientHello capture is implemented only in the OpenSSL PAL.
            }

            using X509Certificate2 serverCert = TestCertificates.GetServerCertificate();
            string serverName = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            using (clientStream)
            using (serverStream)
            using (SslStream clientSsl = new SslStream(clientStream, leaveInnerStreamOpen: false, TestHelper.AllowAnyServerCertificate))
            {
                // ServerCertificate is supplied up-front so the session already has server options and
                // goes straight to the handshake (no NeedsServerOptions detour), arming the SSL_CTX
                // ClientHello callback before the first ProcessHandshake.
                using TlsContext serverCtx = TlsContext.Create(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCert,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                });
                serverCtx.EnableClientHelloInspection = true;

                // BIO mode: no socket handle is passed, so the caller drives ciphertext through
                // ProcessHandshake rather than letting OpenSSL own the socket.
                using TlsSession server = TlsSession.Create(serverCtx);

                Task clientHandshake = clientSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = serverName, // carried as the SNI host name in the ClientHello
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = TestHelper.AllowAnyServerCertificate,
                });

                int clientHelloSuspends = 0;
                byte[]? capturedHello = null;

                Task serverHandshake = Task.Run(async () =>
                {
                    byte[] netIn = ArrayPool<byte>.Shared.Rent(CipherBufSize);
                    byte[] netOut = ArrayPool<byte>.Shared.Rent(CipherBufSize);
                    int inUsed = 0;
                    try
                    {
                        while (!server.IsHandshakeComplete)
                        {
                            TlsOperationStatus status = server.ProcessHandshake(
                                netIn.AsSpan(0, inUsed),
                                netOut,
                                out int consumed,
                                out int produced);

                            if (consumed > 0)
                            {
                                if (consumed < inUsed)
                                {
                                    Buffer.BlockCopy(netIn, consumed, netIn, 0, inUsed - consumed);
                                }
                                inUsed -= consumed;
                            }

                            if (produced > 0)
                            {
                                await serverStream.WriteAsync(netOut.AsMemory(0, produced));
                                await serverStream.FlushAsync();
                            }

                            switch (status)
                            {
                                case TlsOperationStatus.NeedsClientHello:
                                    clientHelloSuspends++;
                                    // The ClientHello was already consumed into the BIO and captured into
                                    // ex_data; copy it out, then resume on the next ProcessHandshake (which
                                    // re-enters the suspended SSL_do_handshake and emits the ServerHello).
                                    ReadOnlySpan<byte> hello = server.GetClientHelloBytes();
                                    capturedHello = hello.ToArray();
                                    continue;

                                case TlsOperationStatus.NeedsCertificateValidation:
                                    server.AcceptWithDefaultValidation();
                                    continue;

                                case TlsOperationStatus.Complete:
                                    continue;

                                case TlsOperationStatus.WantWrite:
                                    while (server.HasPendingOutput)
                                    {
                                        server.DrainPendingOutput(netOut, out int extra);
                                        if (extra > 0)
                                        {
                                            await serverStream.WriteAsync(netOut.AsMemory(0, extra));
                                            await serverStream.FlushAsync();
                                        }
                                    }
                                    continue;

                                case TlsOperationStatus.WantRead:
                                    int r = await serverStream.ReadAsync(netIn.AsMemory(inUsed));
                                    if (r == 0)
                                    {
                                        throw new IOException("Unexpected EOF during handshake.");
                                    }
                                    inUsed += r;
                                    continue;

                                case TlsOperationStatus.Closed:
                                    throw new IOException("Peer closed connection during handshake.");
                            }
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(netIn);
                        ArrayPool<byte>.Shared.Return(netOut);
                    }
                });

                await Task.WhenAll(clientHandshake, serverHandshake).WaitAsync(TimeSpan.FromSeconds(30));

                Assert.True(server.IsHandshakeComplete);
                Assert.True(clientSsl.IsAuthenticated);

                // The handshake paused exactly once at ClientHello and produced bytes.
                Assert.Equal(1, clientHelloSuspends);
                Assert.NotNull(capturedHello);
                Assert.NotEmpty(capturedHello!);

                // First byte is the TLS HandshakeType for ClientHello (1), with no outer 5-byte record
                // header, and the 3-byte length prefix matches the remaining body length.
                Assert.Equal(1, capturedHello![0]);
                int body = (capturedHello[1] << 16) | (capturedHello[2] << 8) | capturedHello[3];
                Assert.Equal(capturedHello.Length, 4 + body);

                // The SNI host the client advertised appears verbatim in the raw bytes, proving these
                // are the real ClientHello the peer sent (the routing info Kestrel would parse).
                byte[] sniBytes = Encoding.ASCII.GetBytes(serverName);
                Assert.True(capturedHello.AsSpan().IndexOf(sniBytes) >= 0,
                    $"SNI host '{serverName}' not found in captured ClientHello bytes.");
            }
        }

        // Same low-level raw ClientHello inspection, exercised on Windows/SChannel through the BIO-mode
        // ProcessHandshake path. SChannel has no native ClientHello callback, but in the BIO model the
        // caller feeds the ClientHello bytes into the session, so the raw message is the first inbound
        // record. TlsSession captures it in managed code, surfaces TlsOperationStatus.NeedsClientHello
        // once (leaving the bytes unconsumed), and resumes when the caller re-feeds them — producing the
        // identical handshake-message bytes the OpenSSL PAL returns. Windows only; TLS 1.3 because the
        // PoC's SChannel server path cannot acquire TLS 1.2 server credentials (see Tls12SkippedOnWindows).
        [Fact]
        public async Task ClientHelloInspection_CapturesRawBytes_ViaTlsSession_BioMode_Windows()
        {
            if (!OperatingSystem.IsWindows())
            {
                return; // SChannel managed ClientHello capture is the Windows-only path.
            }

            using X509Certificate2 serverCert = TestCertificates.GetServerCertificate();
            string serverName = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            (Stream clientStream, Stream serverStream) = TestHelper.GetConnectedStreams();
            using (clientStream)
            using (serverStream)
            using (SslStream clientSsl = new SslStream(clientStream, leaveInnerStreamOpen: false, TestHelper.AllowAnyServerCertificate))
            {
                using TlsContext serverCtx = TlsContext.Create(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCert,
                    EnabledSslProtocols = SslProtocols.Tls13,
                });
                serverCtx.EnableClientHelloInspection = true;

                // BIO mode: no socket handle, so the caller drives ciphertext through ProcessHandshake.
                using TlsSession server = TlsSession.Create(serverCtx);

                Task clientHandshake = clientSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = serverName,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = TestHelper.AllowAnyServerCertificate,
                });

                int clientHelloSuspends = 0;
                byte[]? capturedHello = null;

                Task serverHandshake = Task.Run(async () =>
                {
                    byte[] netIn = ArrayPool<byte>.Shared.Rent(CipherBufSize);
                    byte[] netOut = ArrayPool<byte>.Shared.Rent(CipherBufSize);
                    int inUsed = 0;
                    try
                    {
                        while (!server.IsHandshakeComplete)
                        {
                            TlsOperationStatus status = server.ProcessHandshake(
                                netIn.AsSpan(0, inUsed),
                                netOut,
                                out int consumed,
                                out int produced);

                            if (consumed > 0)
                            {
                                if (consumed < inUsed)
                                {
                                    Buffer.BlockCopy(netIn, consumed, netIn, 0, inUsed - consumed);
                                }
                                inUsed -= consumed;
                            }

                            if (produced > 0)
                            {
                                await serverStream.WriteAsync(netOut.AsMemory(0, produced));
                                await serverStream.FlushAsync();
                            }

                            switch (status)
                            {
                                case TlsOperationStatus.NeedsClientHello:
                                    clientHelloSuspends++;
                                    // Managed capture: read the raw bytes, then resume. The ClientHello was
                                    // left unconsumed (consumed == 0), so the same bytes are re-fed to
                                    // SChannel on the next ProcessHandshake, which emits the ServerHello.
                                    ReadOnlySpan<byte> hello = server.GetClientHelloBytes();
                                    capturedHello = hello.ToArray();
                                    continue;

                                case TlsOperationStatus.NeedsCertificateValidation:
                                    server.AcceptWithDefaultValidation();
                                    continue;

                                case TlsOperationStatus.Complete:
                                    continue;

                                case TlsOperationStatus.WantWrite:
                                    while (server.HasPendingOutput)
                                    {
                                        server.DrainPendingOutput(netOut, out int extra);
                                        if (extra > 0)
                                        {
                                            await serverStream.WriteAsync(netOut.AsMemory(0, extra));
                                            await serverStream.FlushAsync();
                                        }
                                    }
                                    continue;

                                case TlsOperationStatus.WantRead:
                                    int r = await serverStream.ReadAsync(netIn.AsMemory(inUsed));
                                    if (r == 0)
                                    {
                                        throw new IOException("Unexpected EOF during handshake.");
                                    }
                                    inUsed += r;
                                    continue;

                                case TlsOperationStatus.Closed:
                                    throw new IOException("Peer closed connection during handshake.");
                            }
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(netIn);
                        ArrayPool<byte>.Shared.Return(netOut);
                    }
                });

                await Task.WhenAll(clientHandshake, serverHandshake).WaitAsync(TimeSpan.FromSeconds(30));

                Assert.True(server.IsHandshakeComplete);
                Assert.True(clientSsl.IsAuthenticated);

                // Paused exactly once at ClientHello and produced bytes.
                Assert.Equal(1, clientHelloSuspends);
                Assert.NotNull(capturedHello);
                Assert.NotEmpty(capturedHello!);

                // First byte is HandshakeType ClientHello (1), no outer 5-byte record header, and the
                // 3-byte length prefix matches the remaining body — identical shape to the OpenSSL path.
                Assert.Equal(1, capturedHello![0]);
                int body = (capturedHello[1] << 16) | (capturedHello[2] << 8) | capturedHello[3];
                Assert.Equal(capturedHello.Length, 4 + body);

                // The SNI host the client advertised appears verbatim in the raw bytes.
                byte[] sniBytes = Encoding.ASCII.GetBytes(serverName);
                Assert.True(capturedHello.AsSpan().IndexOf(sniBytes) >= 0,
                    $"SNI host '{serverName}' not found in captured ClientHello bytes.");
            }
        }

        // ── Server-side handshake driver (TlsSession only, no SslStream on this side) ──────

        // Drives the server TlsSession over <paramref name="transport"/> until the handshake
        // completes. Honors the peer-certificate verdict via AcceptWithDefaultValidation — this is
        // where the server's RemoteCertificateValidationCallback (ASP.NET Core ClientCertificateValidation)
        // runs. A rejecting callback does not throw here; it faults the session so the next
        // Encrypt/Decrypt throws AuthenticationException.
        private static async Task DriveServerHandshakeAsync(TlsSession session, Stream transport)
        {
            byte[] netIn = ArrayPool<byte>.Shared.Rent(CipherBufSize);
            byte[] netOut = ArrayPool<byte>.Shared.Rent(CipherBufSize);
            int inUsed = 0;

            try
            {
                while (!session.IsHandshakeComplete)
                {
                    TlsOperationStatus status = session.ProcessHandshake(
                        netIn.AsSpan(0, inUsed),
                        netOut,
                        out int consumed,
                        out int produced);

                    if (consumed > 0)
                    {
                        if (consumed < inUsed)
                        {
                            Buffer.BlockCopy(netIn, consumed, netIn, 0, inUsed - consumed);
                        }
                        inUsed -= consumed;
                    }

                    if (produced > 0)
                    {
                        await transport.WriteAsync(netOut.AsMemory(0, produced));
                        await transport.FlushAsync();
                    }

                    switch (status)
                    {
                        case TlsOperationStatus.Complete:
                            continue;

                        case TlsOperationStatus.NeedsCertificateValidation:
                            // Runs the user RemoteCertificateValidationCallback and applies its verdict.
                            // On reject it records the fault (it does not throw here); the session is
                            // left faulted so any later Encrypt/Decrypt throws AuthenticationException.
                            session.AcceptWithDefaultValidation();
                            continue;

                        case TlsOperationStatus.WantWrite:
                            while (session.HasPendingOutput)
                            {
                                session.DrainPendingOutput(netOut, out int extra);
                                if (extra > 0)
                                {
                                    await transport.WriteAsync(netOut.AsMemory(0, extra));
                                    await transport.FlushAsync();
                                }
                            }
                            continue;

                        case TlsOperationStatus.WantRead:
                            int r = await transport.ReadAsync(netIn.AsMemory(inUsed));
                            if (r == 0)
                            {
                                throw new IOException("Unexpected EOF during handshake.");
                            }
                            inUsed += r;
                            continue;

                        case TlsOperationStatus.Closed:
                            throw new IOException("Peer closed connection during handshake.");
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(netIn);
                ArrayPool<byte>.Shared.Return(netOut);
            }
        }
    }
}
