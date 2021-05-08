import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;



public class PublicPrivateKey {

    public static SecretKey createAESKey(int keysize)
            throws Exception
    {
        SecureRandom securerandom
                = new SecureRandom();
        KeyGenerator keygenerator
                = KeyGenerator.getInstance("AES");

        keygenerator.init(keysize, securerandom);
        SecretKey key
                = keygenerator.generateKey();

        return key;
    }

    public static void main(String[] args) {


        try {
            KeyPairGenerator KeyPairGenerator;
            KeyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
            KeyPairGenerator.initialize(1024);
            KeyPair keyPair = KeyPairGenerator.generateKeyPair();

            PublicKey publicA = keyPair.getPublic();
            PrivateKey privateA = keyPair.getPrivate();

            System.out.println("----------Private Key--------");
            System.out.println (Base64.getMimeEncoder().encodeToString( privateA.getEncoded()));
            System.out.println("----------Public Key--------");
            System.out.println (Base64.getMimeEncoder().encodeToString( publicA.getEncoded()));


            SecretKey Symmetrickey
                    = createAESKey(128);

            System.out.println("----------Symmetric Key--------");

            System.out.println(Base64.getMimeEncoder().encodeToString( Symmetrickey.getEncoded()));




            String originalString = Base64.getMimeEncoder().encodeToString(Symmetrickey.getEncoded());
            String encryptedString = AES.encrypt(originalString, Base64.getMimeEncoder().encodeToString(publicA.getEncoded())) ;
            String decryptedString = AES.decrypt(encryptedString, Base64.getMimeEncoder().encodeToString(privateA.getEncoded())) ;

            System.out.println(originalString);
            System.out.println(encryptedString);
            System.out.println(decryptedString);



        } catch (Exception e) {

            e.printStackTrace();
        }


    }

}
