public static byte[] Encrypt(byte[] buf, byte[] key, byte[] iv)
{
	using (var aes = Aes.Create())
    {
		aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Padding = PaddingMode.Zeros;

        aes.Key = key;
        aes.IV = iv;
		
		using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
		{
			return PerformCryptography(buf, encryptor);
		}
	}
}
public static byte[] Decrypt(byte[] buf, byte[] key, byte[] iv)
{
	using (var aes = Aes.Create())
    {
		aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Padding = PaddingMode.Zeros;

        aes.Key = key;
        aes.IV = iv;

        using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
        {
            return PerformCryptography(buf, decryptor);
        }
    }
}

private static byte[] PerformCryptography(byte[] buf, ICryptoTransform cryptoTransform)
{
	using (var ms = new MemoryStream())
    using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
    {
        cryptoStream.Write(buf, 0, buf.Length);
        cryptoStream.FlushFinalBlock();

        return ms.ToArray();
    }
}
		

 string finalPayload = "";
 byte[] key = new byte[] {  };
 byte[] iv = new byte[] {  };
 byte[] decrypted_data = Decrypt(Convert.FromBase64String(finalPayload), key, iv);
