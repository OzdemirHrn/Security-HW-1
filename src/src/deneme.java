import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class deneme {

    public static void main(String... args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom secureRandom = new SecureRandom();

        // First, create the cipher
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        // Then generate the key. Can be 128, 192 or 256 bit
        byte[] key = new byte[256 / 8];
        secureRandom.nextBytes(key);

        // Now generate a nonce. You can also use an ever-increasing counter, which is even more secure. NEVER REUSE A NONCE!
        byte[] nonce = new byte[96 / 8];
        secureRandom.nextBytes(nonce);

        // IV is a nonce followed by a counter (starting at 0). The IV is always 128 bit long.
        // IV in hex looks for example: a2591afec0b2575c50943f2100000000
        //                              |nonce                  |counter
        byte[] iv = new byte[128 / 8];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);
        // No need to explicitly set the counter to 0, as Java arrays are initialized with 0 anyway

        Key keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] plaintext = "Hello World CTR".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plaintext);



    }
}
