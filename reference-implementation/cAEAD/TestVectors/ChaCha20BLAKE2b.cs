using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using cAEAD;

namespace TestVectors;

[TestClass]
public class ChaCha20BLAKE2b
{
    [TestMethod]
    public void TestVector1()
    {
        byte[] plaintext = Convert.FromHexString("5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        byte[] ciphertext = Convert.FromHexString("18337327ef02753bf8d996db218a3697c18943ea6efc86a7e449cb67a7592b9e1715a07771797c93789350528e2e7a8d25b4ca7a7d2968776d50577946cb5da693f1e09309236b7b7495a49a834611b4e67e02d5b24b8a538010ed6c43c30d0f172afe807c064855");
        byte[] computedCiphertext = ChaCha20Blake2b.Encrypt(plaintext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(ciphertext, computedCiphertext));
        byte[] computedPlaintext = ChaCha20Blake2b.Decrypt(computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(plaintext, computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector2()
    {
        byte[] plaintext = Array.Empty<byte>();
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        byte[] ciphertext = Convert.FromHexString("d4ad4bb5a97e0cf9eae5b695ee8f2c3e040241372a28c407abe1fe9accf94d04");
        byte[] computedCiphertext = ChaCha20Blake2b.Encrypt(plaintext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(ciphertext, computedCiphertext));
        byte[] computedPlaintext = ChaCha20Blake2b.Decrypt(computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(plaintext, computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector3()
    {
        byte[] plaintext = Array.Empty<byte>();
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = Convert.FromHexString("76312e302e30");
        byte[] ciphertext = Convert.FromHexString("e048f6d38e774c50e143d422d6d6bf0c970d161aaa32f80145c63e876b470f86");
        byte[] computedCiphertext = ChaCha20Blake2b.Encrypt(plaintext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(ciphertext, computedCiphertext));
        byte[] computedPlaintext = ChaCha20Blake2b.Decrypt(computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(plaintext, computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector4()
    {
        byte[] plaintext = Convert.FromHexString("5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e");
        byte[] nonce = Convert.FromHexString("010000000000000000000000");
        byte[] key = Convert.FromHexString("1001000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        byte[] ciphertext = Convert.FromHexString("db685e0ff12fafd611a832c90e6c7905598ed65babdf6d8cf7057d07b5168673727dda3ef3d6ed2520332c8036e2ce0f72c413290bc4ae41d2d398e4cb2d1f6e906e232ae471ca0e6c12488063dd83b2b45b85d0e9919c420cb64b01a0b49e7189fc3c14e606ac8b");
        byte[] computedCiphertext = ChaCha20Blake2b.Encrypt(plaintext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(ciphertext, computedCiphertext));
        byte[] computedPlaintext = ChaCha20Blake2b.Decrypt(computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(plaintext, computedPlaintext));
    }
    
    [TestMethod]
    public void TestVector5()
    {
        byte[] plaintext = Convert.FromHexString("5468657265277320736f6d6520676f6f6420696e207468697320776f726c642c204d722e2046726f646f2c20616e64206974277320776f727468206669676874696e6720666f722e");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578");
        byte[] computedCiphertext = ChaCha20Blake2b.Encrypt(plaintext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(ciphertext, computedCiphertext));
        byte[] computedPlaintext = ChaCha20Blake2b.Decrypt(computedCiphertext, nonce, key, associatedData);
        Assert.IsTrue(CryptographicOperations.FixedTimeEquals(plaintext, computedPlaintext));
    }

    [TestMethod]
    public void TestVector6()
    {
        byte[] ciphertext = Convert.FromHexString("408319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Blake2b.Decrypt(ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector7()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d579");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Blake2b.Decrypt(ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector8()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578");
        byte[] nonce = Convert.FromHexString("000000000000000000000001");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Blake2b.Decrypt(ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector9()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1003000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = null;
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Blake2b.Decrypt(ciphertext, nonce, key, associatedData));
    }
    
    [TestMethod]
    public void TestVector10()
    {
        byte[] ciphertext = Convert.FromHexString("308319762a72faf302e6d34c2f882c27addc1b2130549e55a084bcdc189c2da0497fdbab20989f24a25f2d3934ac825caaf46ec61a853a06eb97b14c2ced147b94c2223506862d32e183e771eb4a3a03c1875934176577066552fffac50022b3925b9640b4c2d578");
        byte[] nonce = Convert.FromHexString("000000000000000000000000");
        byte[] key = Convert.FromHexString("1002000000000000000000000000000000000000000000000000000000000000");
        byte[] associatedData = Convert.FromHexString("76312e302e30");
        Assert.ThrowsException<CryptographicException>(() => ChaCha20Blake2b.Decrypt(ciphertext, nonce, key, associatedData));
    }
}