// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.IO;

namespace System.Net.Sockets
{
    /// <summary>Represents a Unix Domain Socket endpoint as a path.</summary>
    public sealed partial class UnixDomainSocketEndPoint : EndPoint
    {
        private const AddressFamily EndPointAddressFamily = AddressFamily.Unix;

        private readonly string _path;
        private readonly byte[] _encodedPath;

        // Tracks the file Socket should delete on Dispose.
        internal string? BoundFileName { get; }

        /// <summary>Initializes a new instance of the <see cref="UnixDomainSocketEndPoint"/> with the file path to connect a unix domain socket over.</summary>
        /// <param name="path">The path to connect a unix domain socket over.</param>
        /// <exception cref="ArgumentNullException"><paramref name="path"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="path"/> is of an invalid length for use with domain sockets on this platform. The length must be between 1 and the allowed native path length.</exception>
        /// <exception cref="PlatformNotSupportedException">The current OS does not support Unix Domain Sockets.</exception>
        public UnixDomainSocketEndPoint(string path)
            : this(path, null)
        { }

        private UnixDomainSocketEndPoint(string path, string? boundFileName)
        {
            ArgumentNullException.ThrowIfNull(path);

            BoundFileName = boundFileName;

            // Pathname socket addresses should be null-terminated.
            // Linux abstract socket addresses start with a zero byte, they must not be null-terminated.
            bool isAbstract = IsAbstract(path);
            int bufferLength = Encoding.UTF8.GetByteCount(path);
            if (!isAbstract)
            {
                // for null terminator
                bufferLength++;
            }

            if (path.Length == 0 || bufferLength > s_nativePathLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(path), path,
                    SR.Format(SR.ArgumentOutOfRange_PathLengthInvalid, path, s_nativePathLength));
            }

            _path = path;
            _encodedPath = new byte[bufferLength];
            int bytesEncoded = Encoding.UTF8.GetBytes(path, 0, path.Length, _encodedPath, 0);
            Debug.Assert(bufferLength - (isAbstract ? 0 : 1) == bytesEncoded);

            if (!Socket.OSSupportsUnixDomainSockets)
            {
                throw new PlatformNotSupportedException();
            }
        }

        internal static int MaxAddressSize => s_nativeAddressSize;

        internal UnixDomainSocketEndPoint(SocketAddress socketAddress)
        {
            ArgumentNullException.ThrowIfNull(socketAddress);

            if (socketAddress.Family != EndPointAddressFamily ||
                socketAddress.Size > s_nativeAddressSize)
            {
                throw new ArgumentOutOfRangeException(nameof(socketAddress));
            }

            SetPath(socketAddress.SocketBuffer.Span, out _encodedPath, out _path);
        }


        internal UnixDomainSocketEndPoint(ReadOnlySpan<byte> socketAddress)
        {
            if (socketAddress.Length > s_nativeAddressSize)
            {
                throw new ArgumentOutOfRangeException(nameof(socketAddress));
            }

            SetPath(socketAddress, out _encodedPath, out _path);
        }

        private static void SetPath(ReadOnlySpan<byte> socketAddress, out byte[] encodedPath, out string path)
        {
            if (socketAddress.Length > s_nativePathOffset)
            {
                encodedPath = new byte[socketAddress.Length - s_nativePathOffset];
                for (int i = 0; i < encodedPath.Length; i++)
                {
                    encodedPath[i] = socketAddress[s_nativePathOffset + i];
                }

                // Strip trailing null of pathname socket addresses.
                int length = encodedPath.Length;
                if (!IsAbstract(encodedPath))
                {
                    // Since this isn't an abstract path, we're sure our first byte isn't 0.
                    while (encodedPath[length - 1] == 0)
                    {
                        length--;
                    }
                }
                path = Encoding.UTF8.GetString(encodedPath, 0, length);
            }
            else
            {
                encodedPath = Array.Empty<byte>();
                path = string.Empty;
            }
        }

        /// <summary>Serializes endpoint information into a <see cref="SocketAddress"/> instance.</summary>
        /// <returns>A <see cref="SocketAddress"/> instance that contains the endpoint information.</returns>
        public override SocketAddress Serialize()
        {
            SocketAddress result = CreateSocketAddressForSerialize();

            for (int index = 0; index < _encodedPath.Length; index++)
            {
                result[s_nativePathOffset + index] = _encodedPath[index];
            }

            return result;
        }


        // https://github.com/dotnet/runtime/issues/78993
        internal bool TryGetSocketAddressSize(out int size)
        {
            size = s_nativePathOffset + _encodedPath.Length;
            return true;
        }

        internal void Serialize(Span<byte> destination)
        {
            SocketAddressPal.SetAddressFamily(destination, AddressFamily.Unix);
            _encodedPath.AsSpan().CopyTo(destination.Slice(s_nativePathOffset));
        }

        internal bool TryWriteBytes(Span<byte> destination, out int bytesWritten)
        {
            TryGetSocketAddressSize(out int size);
            if (size > destination.Length)
            {
                bytesWritten = 0;
                return false;
            }

            Serialize(destination);
            bytesWritten = size;
            return true;
        }

        /// <summary>Creates an <see cref="EndPoint"/> instance from a <see cref="SocketAddress"/> instance.</summary>
        /// <param name="socketAddress">The socket address that serves as the endpoint for a connection.</param>
        /// <returns>A new <see cref="EndPoint"/> instance that is initialized from the specified <see cref="SocketAddress"/> instance.</returns>
        public override EndPoint Create(SocketAddress socketAddress) => new UnixDomainSocketEndPoint(socketAddress);

        /// <summary>Gets the address family to which the endpoint belongs.</summary>
        /// <value>One of the <see cref="AddressFamily"/> values.</value>
        public override AddressFamily AddressFamily => EndPointAddressFamily;

        /// <summary>Gets the path represented by this <see cref="UnixDomainSocketEndPoint"/> instance.</summary>
        /// <returns>The path represented by this <see cref="UnixDomainSocketEndPoint"/> instance.</returns>
        public override string ToString()
        {
            bool isAbstract = IsAbstract(_path);
            if (isAbstract)
            {
                return string.Concat("@", _path.AsSpan(1));
            }
            else
            {
                return _path;
            }
        }

        /// <summary>Determines whether the specified <see cref="object"/> is equal to the current <see cref="UnixDomainSocketEndPoint"/>.</summary>
        /// <param name="obj">The <see cref="object"/> to compare with the current <see cref="UnixDomainSocketEndPoint"/>.</param>
        /// <returns><see langword="true"/> if the specified <see cref="object"/> is equal to the current <see cref="UnixDomainSocketEndPoint"/>; otherwise, <see langword="false"/>.</returns>
        public override bool Equals([NotNullWhen(true)] object? obj)
            => obj is UnixDomainSocketEndPoint ep && _path == ep._path;

        /// <summary>Returns a hash value for a <see cref="UnixDomainSocketEndPoint"/> instance.</summary>
        /// <returns>An integer hash value.</returns>
        public override int GetHashCode() => _path.GetHashCode();

        internal UnixDomainSocketEndPoint CreateBoundEndPoint()
        {
            if (IsAbstract(_path))
            {
                return this;
            }

            return new UnixDomainSocketEndPoint(_path, Path.GetFullPath(_path));
        }

        internal UnixDomainSocketEndPoint CreateUnboundEndPoint()
        {
            if (IsAbstract(_path) || BoundFileName is null)
            {
                return this;
            }

            return new UnixDomainSocketEndPoint(_path, null);
        }

        private static bool IsAbstract(string path) => path.Length > 0 && path[0] == '\0';

        private static bool IsAbstract(byte[] encodedPath) => encodedPath.Length > 0 && encodedPath[0] == 0;
    }
}
