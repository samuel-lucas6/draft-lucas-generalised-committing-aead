using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using cAEAD;
using Geralt;

namespace TestVectors;

[TestClass]
public class ChaCha20Blake2b
{
    [TestMethod]
    public void TestVector1()
    {
        byte[] plaintext = Convert.FromHexString("5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        byte[] ciphertext = Convert.FromHexString("18337327ef02753bf8d996db218a3697c18943ea6efc86a7e449cb67a7592b9e1715a07771797c93789350528e2e7a8d25b4ca7a7d2968776d50577946cb5da693f1e09309236b7bdb04001a8feeab7de48946f08df1cfd0ce03a719232ea7106efb8706e40d7cb6");
        var computedCiphertext = new byte[plaintext.Length + BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Encrypt(computedCiphertext, plaintext, nonce, key, associatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(computedCiphertext));
        var computedPlaintext = new byte[computedCiphertext.Length - BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Decrypt(computedPlaintext, computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(plaintext.SequenceEqual(computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector2()
    {
        byte[] plaintext = Array.Empty<byte>();
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        byte[] ciphertext = Convert.FromHexString("a1ad6c7c4a9bb8201cf72904ebea1fed709c75ded85adaea7034bdbba1b5ec4f");
        var computedCiphertext = new byte[plaintext.Length + BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Encrypt(computedCiphertext, plaintext, nonce, key, associatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(computedCiphertext));
        var computedPlaintext = new byte[computedCiphertext.Length - BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Decrypt(computedPlaintext, computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(plaintext.SequenceEqual(computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector3()
    {
        byte[] plaintext = Array.Empty<byte>();
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = Convert.FromHexString("76312e302e30");
        byte[] ciphertext = Convert.FromHexString("c0deb4501fe4cc651687cff8c9f5377072d4788cfe2d0f51dd97fab7b16fab84");
        var computedCiphertext = new byte[plaintext.Length + BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Encrypt(computedCiphertext, plaintext, nonce, key, associatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(computedCiphertext));
        var computedPlaintext = new byte[computedCiphertext.Length - BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Decrypt(computedPlaintext, computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(plaintext.SequenceEqual(computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector4()
    {
        byte[] plaintext = Convert.FromHexString("5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e");
        byte[] nonce = Convert.FromHexString("010000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        byte[] ciphertext = Convert.FromHexString("db685e0ff12fafd611a832c90e6c7905598ed65babdf6d8cf7057d07b5168673727dda3ef3d6ed2520332c8036e2ce0f72c413290bc4ae41d2d398e4cb2d1f6e906e232ae471ca0ea4ade513d685a4fab9a886fa885b6f6b54ff04d66612cfdde669bd0dbda23f54");
        var computedCiphertext = new byte[plaintext.Length + BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Encrypt(computedCiphertext, plaintext, nonce, key, associatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(computedCiphertext));
        var computedPlaintext = new byte[computedCiphertext.Length - BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Decrypt(computedPlaintext, computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(plaintext.SequenceEqual(computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector5()
    {
        byte[] plaintext = Convert.FromHexString("5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3");
        var computedCiphertext = new byte[plaintext.Length + BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Encrypt(computedCiphertext, plaintext, nonce, key, associatedData);
        Assert.IsTrue(ciphertext.SequenceEqual(computedCiphertext));
        var computedPlaintext = new byte[computedCiphertext.Length - BLAKE2b.TagSize];
        ChaCha20BLAKE2b.Decrypt(computedPlaintext, computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(plaintext.SequenceEqual(computedPlaintext));
    }

    [TestMethod]
    public void TestVector6()
    {
        byte[] ciphertext = Convert.FromHexString("408319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3");
        var plaintext = new byte[ciphertext.Length - BLAKE2b.TagSize];
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20BLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector7()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b4");
        var plaintext = new byte[ciphertext.Length - BLAKE2b.TagSize];
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20BLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector8()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3");
        var plaintext = new byte[ciphertext.Length - BLAKE2b.TagSize];
        byte[] nonce = Convert.FromHexString("000000000000000000000001");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20BLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector9()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3");
        var plaintext = new byte[ciphertext.Length - BLAKE2b.TagSize];
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1003000000000000000000000000000000000000000000000000000000000000");
        byte[]? associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20BLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector10()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32af0be2b1f658597412e65d77560844eee38a190063300c8e8a8c62ea25b943b3");
        var plaintext = new byte[ciphertext.Length - BLAKE2b.TagSize];
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = Convert.FromHexString("76312e302e30");
        Assert.ThrowsException<CryptographicException>(() => ChaCha20BLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData));
    }
}