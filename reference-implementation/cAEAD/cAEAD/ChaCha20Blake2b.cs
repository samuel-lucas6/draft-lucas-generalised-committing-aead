using System.Text;
using System.Security.Cryptography;
using Sodium;

namespace cAEAD;

// This reference implementation is using libsodium as the cryptographic library for ChaCha20 and BLAKE2b
// ChaCha20Ietf refers to the unauthenticated ChaCha20 from RFC 8439
// GenericHash refers to keyed BLAKE2b from RFC 7693
public static class ChaCha20Blake2b
{
    // Constants no matter the cipher and collision resistant, hash-based MAC
    // C# arrays cannot be greater than int.MaxValue by default
    private const int K_LEN = 32;
    private const int A_MAX = int.MaxValue;
    private const int T_LEN = 32;
    
    // Constants specific to ChaCha20-BLAKE2b
    private const int N_MIN = 12;
    private const int P_MAX = int.MaxValue - T_LEN;
    private const int C_MAX = P_MAX + T_LEN;
    private const string ENCRYPTION_CONTEXT = "ChaCha20.Encrypt()";
    private const string MAC_CONTEXT = "BLAKE2b.KeyedHash()";

    public static byte[] Encrypt(byte[] plaintext, byte[] nonce, byte[] key, byte[]? associatedData = null)
    {
        if (plaintext == null || plaintext.Length >= P_MAX) { throw new ArgumentOutOfRangeException(nameof(plaintext), $"The {nameof(plaintext)} length must be less than {P_MAX}."); }
        if (nonce == null || nonce.Length != N_MIN) { throw new ArgumentOutOfRangeException(nameof(nonce), $"The {nameof(nonce)} length must be equal to {N_MIN}."); }
        if (key == null || key.Length != K_LEN) { throw new ArgumentOutOfRangeException(nameof(key), $"The {nameof(key)} length must be equal to {K_LEN}."); }
        if (associatedData != null && associatedData.Length >= A_MAX) { throw new ArgumentOutOfRangeException(nameof(associatedData), $"The {nameof(associatedData)} length must be less than {A_MAX}."); }
        associatedData ??= Array.Empty<byte>();
        
        (byte[] encryptionKey, byte[] macKey) = DeriveKeys(key, nonce);
        
        byte[] ciphertext = StreamEncryption.EncryptChaCha20Ietf(plaintext, nonce, encryptionKey);
        
        byte[] tag = ComputeTag(associatedData, ciphertext, macKey);
        
        CryptographicOperations.ZeroMemory(encryptionKey);
        CryptographicOperations.ZeroMemory(macKey);
        
        return Concat(ciphertext, tag);
    }
    
    public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key, byte[]? associatedData = null)
    {
        if (ciphertext == null || ciphertext.Length >= C_MAX) { throw new ArgumentOutOfRangeException(nameof(ciphertext), $"The {nameof(ciphertext)} length must be less than {C_MAX}."); }
        if (nonce == null || nonce.Length != N_MIN) { throw new ArgumentOutOfRangeException(nameof(nonce), $"The {nameof(nonce)} length must be equal to {N_MIN}."); }
        if (key == null || key.Length != K_LEN) { throw new ArgumentOutOfRangeException(nameof(key), $"The {nameof(key)} length must be equal to {K_LEN}."); }
        if (associatedData != null && associatedData.Length >= A_MAX) { throw new ArgumentOutOfRangeException(nameof(associatedData), $"The {nameof(associatedData)} length must be less than {A_MAX}."); }
        associatedData ??= Array.Empty<byte>();
        
        var tag = new byte[T_LEN];
        Array.Copy(ciphertext, sourceIndex: ciphertext.Length - tag.Length, tag, destinationIndex: 0, tag.Length);
        
        var ciphertextNoTag = new byte[ciphertext.Length - tag.Length];
        Array.Copy(ciphertext, ciphertextNoTag, ciphertextNoTag.Length);
        
        (byte[] encryptionKey, byte[] macKey) = DeriveKeys(key, nonce);

        byte[] computedTag = ComputeTag(associatedData, ciphertextNoTag, macKey);
        
        CryptographicOperations.ZeroMemory(macKey);
        
        if (CryptographicOperations.FixedTimeEquals(tag, computedTag) == false)
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
            throw new CryptographicException("Authentication failed.");
        }
        byte[] plaintext = StreamEncryption.DecryptChaCha20Ietf(ciphertextNoTag, nonce, encryptionKey);
        CryptographicOperations.ZeroMemory(encryptionKey);
        return plaintext;
    }

    private static (byte[] encryptionKey, byte[] macKey) DeriveKeys(byte[] key, byte[] nonce)
    {
        byte[] encryptionKey = GenericHash.Hash(Encoding.UTF8.GetBytes(ENCRYPTION_CONTEXT), key, K_LEN);
        byte[] macKey = GenericHash.Hash(Concat(Encoding.UTF8.GetBytes(MAC_CONTEXT), nonce), key, K_LEN);
        return (encryptionKey, macKey);
    }
    
    private static byte[] ComputeTag(byte[] associatedData, byte[] ciphertext, byte[] macKey)
    {
        return GenericHash.Hash(Concat(associatedData, ciphertext, LE64(associatedData.Length), LE64(ciphertext.Length)), macKey, T_LEN);
    }
    
    private static byte[] LE64(int x)
    {
        var xBytes = BitConverter.GetBytes((ulong) x);
        // BitConverter automatically detects the computer's architecture
        if (!BitConverter.IsLittleEndian) { Array.Reverse(xBytes); }
        return xBytes;
    }
    
    private static T[] Concat<T>(params T[][] arrays)
    {
        int offset = 0;
        var result = new T[arrays.Sum(array => array.Length)];
        foreach (var array in arrays)
        {
            Array.Copy(array, sourceIndex: 0, result, destinationIndex: offset, array.Length);
            offset += array.Length;
        }
        return result;
    }
}