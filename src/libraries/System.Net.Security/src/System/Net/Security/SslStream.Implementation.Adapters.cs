// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Security
{
    // This contains adapters to allow a single code path for sync/async logic
    public partial class SslStream
    {
        private interface ISslIOAdapter
        {
            bool IsAsync();
            ValueTask<int> ReadAsync(byte[] buffer, int offset, int count);
            ValueTask WriteAsync(byte[] buffer, int offset, int count);
            CancellationToken CancellationToken { get; }
        }

        private readonly struct AsyncSslIOAdapter : ISslIOAdapter
        {
            private readonly SslStream _sslStream;
            private readonly CancellationToken _cancellationToken;

            public bool IsAsync() => true;
            public AsyncSslIOAdapter(SslStream sslStream, CancellationToken cancellationToken)
            {
                _cancellationToken = cancellationToken;
                _sslStream = sslStream;
            }

            public ValueTask<int> ReadAsync(byte[] buffer, int offset, int count) => _sslStream.InnerStream.ReadAsync(new Memory<byte>(buffer, offset, count), _cancellationToken);

            public ValueTask WriteAsync(byte[] buffer, int offset, int count) => _sslStream.InnerStream.WriteAsync(new ReadOnlyMemory<byte>(buffer, offset, count), _cancellationToken);

            public CancellationToken CancellationToken => _cancellationToken;
        }

        private readonly struct SyncSslIOAdapter : ISslIOAdapter
        {
            private readonly SslStream _sslStream;

            public bool IsAsync() => false;
            public SyncSslIOAdapter(SslStream sslStream) => _sslStream = sslStream;

            public ValueTask<int> ReadAsync(byte[] buffer, int offset, int count) => new ValueTask<int>(_sslStream.InnerStream.Read(buffer, offset, count));

            public ValueTask WriteAsync(byte[] buffer, int offset, int count)
            {
                _sslStream.InnerStream.Write(buffer, offset, count);
                return default;
            }

            public CancellationToken CancellationToken => default;
        }
    }
}
