import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class PublicPrivateKey {
    public static void main(String args[]) throws Exception {


        //Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

        //Initializing the key pair generator
        keyPairGen.initialize(2048);

        //Generate the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();

        //Getting the public key from the key pair
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();


        System.out.println("----------Private Key--------");
        String privateKeyStr = Base64.getMimeEncoder().encodeToString(privateKey.getEncoded());
        System.out.println(privateKeyStr);

        System.out.println("----------Public Key--------");
        String publicKeyStr = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
        System.out.println(publicKeyStr);

        SecretKey Symmetrickey = SymmetricKey.createAESKey(128);

        String symmetricKeyStr = Base64.getMimeEncoder().encodeToString(Symmetrickey.getEncoded());
        System.out.println("----------Symmetric Key--------");
        System.out.println(symmetricKeyStr);


        //Creating a Cipher object
        Cipher cipher = Cipher.getInstance("RSA");

        //Initializing a Cipher object
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Add data to the cipher
        byte[] input = symmetricKeyStr.getBytes();
        cipher.update(input);

        //encrypting the data
        byte[] cipherText = cipher.doFinal();
        System.out.println("---------Encrypted---------");
        System.out.println(new String(cipherText, StandardCharsets.UTF_8));

        //Initializing the same cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Decrypting the text
        System.out.println("---------Decrypted---------");
        byte[] decipheredText = cipher.doFinal(cipherText);
        System.out.println(new String(decipheredText));
    }

    public static class SymmetricKey {

        public static SecretKey createAESKey(int keySize)
                throws Exception {
            SecureRandom securerandom = new SecureRandom();
            KeyGenerator keygenerator = KeyGenerator.getInstance("AES");

            keygenerator.init(keySize, securerandom);

            return keygenerator.generateKey();
        }
    }


}