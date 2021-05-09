import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class AES {
    // 16 chars -> 16 bytes -> 128 bits key, 32 chars -> 32 bytes -> 256 bits
    private static  String[] keys = null;

    static {
        try {
            keys = new String[]{PublicPrivateKey.symmetricKeyGenerator(128),
                    PublicPrivateKey.symmetricKeyGenerator(256)};
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String[] initVectors;
    private static String path = "C:\\Users\\hrnoz\\IdeaProjects\\OzdemirHrn-Security-HW-1\\src\\";


    public static void main(String[] args) throws Exception {

        File f = new File(path + "jordan.jpg");
        String originalImage = encodeFileToBase64Binary(f);
//        System.out.println("--------------------Encoded image--------------------\n" + originalImage);
//        System.out.println("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

        AES(originalImage, 128);


    }

    public static void initializeIV() {
        initVectors = new String[]{randomString(128), randomString(256)};
    }

    public static void AES(String originalImage, int keySize) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[12]; // 96 bits
        secureRandom.nextBytes(nonce);
        // Encryption
        // c) timer start
        long start = System.nanoTime();
        initializeIV();
        String encrypted = encrypt(originalImage, keySize, nonce);
        long elapsedTimeOfEncryption = System.nanoTime() - start;

        // timer stop
        System.out.println("--------------------a) Encryption by AES 128 bit key--------------------");
        System.out.println(encrypted);
        System.out.println("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

        //Decryption
        String decrypted = decrypt(encrypted, keySize, nonce);
        System.out.println("--------------------b) Decryption--------------------");
        System.out.println(decrypted);
        System.out.println("\n\nAre decrypted string and original string the same?: " + originalImage.equals(decrypted));


        System.out.println("\n\n--------------------d) Different IV--------------------");
        initializeIV();
        System.out.println("Are cipher texts the same?: " + encrypted.equals(encrypt(originalImage, keySize, nonce)));


        long convert = TimeUnit.MILLISECONDS.convert(elapsedTimeOfEncryption, TimeUnit.NANOSECONDS);
        System.out.println("\nEncryption Time is "+convert);
    }

    /**
     * Produces random string
     *
     * @param keySize is in bits
     * @return produced random string
     */
    public static String randomString(int keySize) {
        int size = keySize / 8;
        String str = "";
        String lowercase = "abcdefghijklmnoprstuvyzqwx";
        String uppercase = "ABCDEFGHIJKLMNOPRSTUVYZQWX";
        String digits = "0123456789";
        int index;
        int row;
        for (int i = 0; i < size; i++) {
            row = (int) (Math.random() * 3);
            if (row == 2) {
                index = (int) (Math.random() * 10);
                str += digits.charAt(index);
            } else if (row == 1) {
                index = (int) (Math.random() * 26);
                str += uppercase.charAt(index);
            } else {
                index = (int) (Math.random() * 26);
                str += lowercase.charAt(index);
            }
        }
        return str;
    }

    private static String encodeFileToBase64Binary(File file) throws Exception {
        FileInputStream fileInputStreamReader = new FileInputStream(file);
        byte[] bytes = new byte[(int) file.length()];
        fileInputStreamReader.read(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * AES Encryption
     *
     * @param value   to be encrypted
     * @param keySize is in bits
     * @return encrypted string or null
     */
    public static String encrypt(String value, int keySize, byte[] nonce) {
        String key, initVector;
        if (keySize == 128) {
            key = keys[0];
            initVector = initVectors[0];
        } else {
            key = keys[1];
            initVector = initVectors[1];
        }
        try {

            byte[] ivCTR = new byte[128 / 8];
            System.arraycopy(nonce, 0, ivCTR, 0, nonce.length);
            IvParameterSpec ivSpec = new IvParameterSpec(ivCTR);



            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * AES Decryption
     *
     * @param encrypted to be encrypted
     * @param keySize   is in bits
     * @return decrypted string or null
     */
    public static String decrypt(String encrypted, int keySize, byte[] nonce) {
        String key, initVector;
        if (keySize == 128) {
            key = keys[0];
            initVector = initVectors[0];
        } else {
            key = keys[1];
            initVector = initVectors[1];
        }
        try {

            byte[] ivCTR = new byte[128 / 8];
            System.arraycopy(nonce, 0, ivCTR, 0, nonce.length);
            IvParameterSpec ivSpec = new IvParameterSpec(ivCTR);



            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/NOPADDING");



            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
