using System.Text;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

// This reference implementation uses libsodium as the cryptographic library for ChaCha20 and BLAKE2b
public static class ChaCha20BLAKE2b
{
    // Constants no matter the cipher and collision-resistant, hash-based MAC
    private const int K_LEN = 32;
    private const int T_LEN = 32;
    private const int UInt64BytesLength = 8;
    private const int BothUInt64BytesLengths = UInt64BytesLength * 2;
    
    // Constants specific to ChaCha20-BLAKE2b
    // C# arrays cannot be greater than int.MaxValue
    private const int N_MIN = 12;
    private const int P_MAX = int.MaxValue - BothUInt64BytesLengths - T_LEN;
    private const int C_MAX = P_MAX + T_LEN;
    private const string ENCRYPTION_CONTEXT = "ChaCha20.Encrypt()";
    private const string MAC_CONTEXT = "BLAKE2b-256.KeyedHash()";
    
    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (plaintext.Length >= P_MAX) { throw new ArgumentOutOfRangeException(nameof(plaintext), $"The {nameof(plaintext)} length must be less than {P_MAX}."); }
        if (ciphertext.Length != plaintext.Length + T_LEN) { throw new ArgumentOutOfRangeException(nameof(ciphertext), $"The {nameof(ciphertext)} length must be equal to {plaintext.Length + T_LEN}."); }
        if (nonce.Length != N_MIN) { throw new ArgumentOutOfRangeException(nameof(nonce), $"The {nameof(nonce)} length must be equal to {N_MIN}."); }
        if (key.Length != K_LEN) { throw new ArgumentOutOfRangeException(nameof(key), $"The {nameof(key)} length must be equal to {K_LEN}."); }
        if (associatedData != default) { int overflowCheck = checked(plaintext.Length + associatedData.Length + BothUInt64BytesLengths); }
        
        Span<byte> encryptionKey = stackalloc byte[K_LEN], macKey = stackalloc byte[K_LEN];
        DeriveKeys(encryptionKey, macKey, nonce, key);
        
        Span<byte> ciphertextNoTag = new byte[plaintext.Length];
        ChaCha20.Encrypt(ciphertextNoTag, plaintext, nonce, encryptionKey);
        
        Span<byte> tag = stackalloc byte[T_LEN];
        ComputeTag(tag, associatedData, ciphertextNoTag, macKey);
        
        CryptographicOperations.ZeroMemory(encryptionKey);
        CryptographicOperations.ZeroMemory(macKey);
        
        if (ciphertextNoTag.Length == 0) {
            tag.CopyTo(ciphertext);
        }
        else {
            Spans.Concat(ciphertext, ciphertextNoTag, tag);
        }
    }
    
    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length >= C_MAX) { throw new ArgumentOutOfRangeException(nameof(ciphertext), $"The {nameof(ciphertext)} length must be less than {C_MAX}."); }
        if (plaintext.Length != ciphertext.Length - T_LEN) { throw new ArgumentOutOfRangeException(nameof(plaintext), $"The {nameof(plaintext)} length must be equal to {ciphertext.Length - T_LEN}."); }
        if (nonce.Length != N_MIN) { throw new ArgumentOutOfRangeException(nameof(nonce), $"The {nameof(nonce)} length must be equal to {N_MIN}."); }
        if (key.Length != K_LEN) { throw new ArgumentOutOfRangeException(nameof(key), $"The {nameof(key)} length must be equal to {K_LEN}."); }
        if (associatedData != default) { int overflowCheck = checked(plaintext.Length + associatedData.Length + BothUInt64BytesLengths); }
        
        ReadOnlySpan<byte> tag = ciphertext.Slice(start: ciphertext.Length - T_LEN);
        
        ReadOnlySpan<byte> ciphertextNoTag = ciphertext.Slice(start: 0, ciphertext.Length - tag.Length);
        
        Span<byte> encryptionKey = stackalloc byte[K_LEN], macKey = stackalloc byte[K_LEN];
        DeriveKeys(encryptionKey, macKey, nonce, key);
        
        Span<byte> computedTag = stackalloc byte[T_LEN];
        ComputeTag(computedTag, associatedData, ciphertextNoTag, macKey);
        
        CryptographicOperations.ZeroMemory(macKey);
        
        if (ConstantTime.Equals(tag, computedTag) == false) {
            CryptographicOperations.ZeroMemory(encryptionKey);
            throw new CryptographicException("Authentication failed.");
        }
        
        ChaCha20.Decrypt(plaintext, ciphertextNoTag, nonce, encryptionKey);
        CryptographicOperations.ZeroMemory(encryptionKey);
    }

    private static void DeriveKeys(Span<byte> encryptionKey, Span<byte> macKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        BLAKE2b.ComputeTag(encryptionKey, Encoding.UTF8.GetBytes(ENCRYPTION_CONTEXT), key);
        BLAKE2b.ComputeTag(macKey, Arrays.Concat(Encoding.UTF8.GetBytes(MAC_CONTEXT), nonce.ToArray()), key);
    }
    
    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> macKey)
    {
        byte[] associatedDataLength = new byte[UInt64BytesLength], ciphertextLength = new byte[UInt64BytesLength];
        BinaryPrimitives.WriteUInt64LittleEndian(associatedDataLength, (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(ciphertextLength, (ulong)ciphertext.Length);
        Span<byte> message = Arrays.Concat(associatedData.ToArray(), ciphertext.ToArray(), associatedDataLength, ciphertextLength);
        BLAKE2b.ComputeTag(tag, message, macKey);
    }
}