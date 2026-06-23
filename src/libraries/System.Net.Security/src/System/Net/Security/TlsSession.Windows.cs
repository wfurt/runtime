// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Security
{
    public sealed partial class TlsSession
    {
        // Windows/SChannel raw ClientHello inspection.
        //
        // Unlike OpenSSL (where SSL_CTX_set_client_hello_cb captures the message natively inside
        // SSL_do_handshake), SChannel exposes no ClientHello callback. But in the BIO/ProcessHandshake
        // model the caller hands the ClientHello bytes *into* the session, so the raw message is simply
        // the first inbound TLS record. We capture it in managed code before SChannel's first
        // AcceptSecurityContext call, surface NeedsClientHello once, and let the caller re-feed the same
        // (unconsumed) bytes on resume. The bytes match the OpenSSL shape exactly: the TLS handshake
        // message (HandshakeType + 3-byte length + body), with no outer 5-byte record header.

        private byte[]? _capturedClientHello;
        private bool _clientHelloInspected;

        partial void TryCaptureClientHelloForInspection(ReadOnlySpan<byte> input, ref TlsOperationStatus? suspend)
        {
            if (_clientHelloInspected || !_options.EnableClientHelloCallback)
            {
                return;
            }

            // The frame guard in ProcessHandshake has already ensured the full first record is present
            // before the server branch runs, so header.Length bytes are available here.
            TlsFrameHeader header = default;
            if (!TlsFrameHelper.TryGetFrameHeader(input, ref header) ||
                header.Type != TlsContentType.Handshake ||
                input.Length < header.Length)
            {
                return;
            }

            int payloadLength = header.Length - TlsFrameHelper.HeaderSize;
            if (payloadLength < 4)
            {
                return;
            }

            ReadOnlySpan<byte> payload = input.Slice(TlsFrameHelper.HeaderSize, payloadLength);
            if (payload[0] != (byte)TlsHandshakeType.ClientHello)
            {
                return;
            }

            int bodyLength = (payload[1] << 16) | (payload[2] << 8) | payload[3];
            int messageLength = 4 + bodyLength;
            if (messageLength > payloadLength)
            {
                // The ClientHello spans more than one TLS record (rare: very large ECH/PQ hellos).
                // Managed capture only reassembles a single record, so skip inspection here rather
                // than surface truncated bytes — SChannel still completes the handshake normally.
                _clientHelloInspected = true;
                return;
            }

            _capturedClientHello = payload.Slice(0, messageLength).ToArray();
            _clientHelloInspected = true;
            suspend = TlsOperationStatus.NeedsClientHello;
        }

        partial void TryGetClientHelloBytes(ref ReadOnlySpan<byte> result)
        {
            if (_capturedClientHello is not null)
            {
                result = _capturedClientHello;
            }
        }
    }
}
