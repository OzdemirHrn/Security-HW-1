import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


/**
 * This class responsible for generating public private keys
 * and symmetric key size of 128 and 256 bits
 */
public class PublicPrivateKey {

    /**
     * This method generates symmetric key according to the key siz
     * @param keySize 128 bit or 256 bit key size
     * @return String format of symmetric key
     */
    public static byte[] symmetricKeyGenerator(int keySize) throws Exception {
        SecretKey symmetricKey = SymmetricKey.createAESKey(keySize);
        return (symmetricKey.getEncoded());

    }

    public static void main(String...args) throws Exception {


        //We are creating rsa key pair
        KeyPairGenerator rasKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //key siz is 2048 bit
        rasKeyPairGenerator.initialize(2048);

        //we are generating the pair of keys
        KeyPair pairOfKey = rasKeyPairGenerator.generateKeyPair();

        //we are generating the public key from the key pair
        PublicKey publicKey = pairOfKey.getPublic();
        //we are generating the private key from the key pair
        PrivateKey privateKey = pairOfKey.getPrivate();

        // we are converting to private key to string. and printing this String
        System.out.println("----------Private Key--------");
        String privateKeyStr = Base64.getMimeEncoder().encodeToString(privateKey.getEncoded());
        System.out.println(privateKeyStr);

        // we are converting to public key to string. and printing this String
        System.out.println("----------Public Key--------");
        String publicKeyStr = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
        System.out.println(publicKeyStr);


        // Creating new Symmetric key with 128 keySize and we are printing this symmetricKey
        String symmetricKeyStr128 = Base64.getMimeEncoder().encodeToString(symmetricKeyGenerator(128));
        System.out.println("----------Symmetric Key 128 bit--------");
        System.out.println(symmetricKeyStr128);

        // Creating new Symmetric key with 256 keySize and we are printing this symmetricKey
        String symmetricKeyStr256 = Base64.getMimeEncoder().encodeToString(symmetricKeyGenerator(256));
        System.out.println("----------Symmetric Key 256 bit--------");
        System.out.println(symmetricKeyStr256);

        //Creating new Cipher with RSA
        Cipher cipher = Cipher.getInstance("RSA");
        //We encrypted these symmetric keys with public key
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Bytes of 128bit symmetric key
        byte[] cipherSymmetric128 = symmetricKeyStr128.getBytes();
        cipher.update(cipherSymmetric128);

        //encrypting the data
        byte[] cipherText128 = cipher.doFinal();
        System.out.println("---------Encrypted Symmetric Key 128 bit---------");
        System.out.println(bytesToHex(cipherText128));


        //Decrypting the text
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        System.out.println("---------Decrypted Symmetric Key 128 bit---------");
        byte[] decipheredText128 = cipher.doFinal(cipherText128);

        System.out.println(new String(decipheredText128,StandardCharsets.UTF_8));


        //We encrypted these symmetric keys with public key
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        //Bytes of 256bit symmetric key
        byte[] cipherSymmetric256 = symmetricKeyStr256.getBytes();
        cipher.update(cipherSymmetric256);


        //encrypting the data
        byte[] cipherText256 = cipher.doFinal();
        System.out.println("---------Encrypted Symmetric Key 256 bit---------");
        System.out.println(bytesToHex(cipherText256));

        //Decrypting the text
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        System.out.println("---------Decrypted Symmetric Key 256 bit---------");
        byte[] decipheredText256 = cipher.doFinal(cipherText256);
        System.out.println(new String(decipheredText256,StandardCharsets.UTF_8));


        System.out.println("\nSENDER");

        String originalString = "Kobe Bean Bryant (August 23, 1978 \u2013 January 26, 2020) was an American professional basketball player. A shooting guard, he spent his entire 20-year career with the Los Angeles Lakers in the National Basketball Association (NBA). Regarded as one of the greatest players of all time, Bryant won five NBA championships, was an 18-time All-Star, a 15-time member of the All-NBA Team, a 12-time member of the All-Defensive Team, the 2008 NBA Most Valuable Player (MVP), and a two-time NBA Finals MVP. Bryant also led the NBA in scoring twice, and ranks fourth in league all-time regular season and postseason scoring.\n" +
                "\n" +
                "Born in Philadelphia and partly raised in Italy, Bryant was recognized as the top American high-school basketball player while at Lower Merion. The son of former NBA player Joe Bryant, he declared for the 1996 NBA draft and was selected by the Charlotte Hornets with the 13th overall pick; he was then traded to the Lakers. As a rookie, Bryant earned a reputation as a high-flyer by winning the 1997 Slam Dunk Contest, and was named an All-Star by his second season. Despite a feud with teammate Shaquille O'Neal, the pair led the Lakers to three consecutive NBA championships from 2000 to 2002. In 2003, Bryant was charged with sexual assault; criminal charges were dropped after the accuser refused to testify, and a civil suit was settled out of court, with Bryant issuing a public apology and admitting to a consensual sexual encounter.\n" +
                "\n" +
                "After the Lakers lost the 2004 NBA Finals, O'Neal was traded and Bryant became the cornerstone of the Lakers. He led the NBA in scoring in the 2005–06 and 2006–07 seasons. In 2006, he scored a career-high 81 points; the second most points scored in a single game in league history, behind Wilt Chamberlain's 100-point game in 1962. Bryant led the team to consecutive championships in 2009 and 2010, both times being named NBA Finals MVP. He continued to be among the top players in the league through the 2012-13 season, when he suffered a torn achilles tendon at age 34. Season-ending knee and shoulder injuries followed in the next two seasons. Citing physical decline, Bryant retired after the 2015-16 season.\n" +
                "\n" +
                "The all-time leading scorer in Lakers history, Bryant was the first guard in NBA history to play 20 seasons. His 18 All-Star designations are the second most all time, while it is the record for most consecutive appearances as a starter. Bryant's four All-Star Game MVP Awards are tied with Bob Pettit for the most in NBA history. He gave himself the nickname \"Black Mamba\" in the mid-2000s, and the epithet became widely adopted by the general public. At the 2008 and 2012 Summer Olympics, he won two gold medals as a member of the U.S. national team. In 2018, he won the Academy Award for Best Animated Short Film for the film Dear Basketball (2017).\n" +
                "\n" +
                "Bryant died, along with his daughter Gianna and seven others, in a helicopter crash in Calabasas, California. A number of tributes and memorials were subsequently issued, including renaming the All-Star MVP Award in his honor.";

        //SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(
                originalString.getBytes(StandardCharsets.UTF_8));

        System.out.println("\n---------Hash(text)---------");
        System.out.println(bytesToHex(encodedhash));
        // SENDER
        //initialize cipher with private key
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        // update cipher with Hash(m)
        cipher.update(encodedhash);


        //encrypting the data
        byte[] cipherText = cipher.doFinal();
        System.out.println("---------Encrypted H(m)---------");
        System.out.println(bytesToHex(cipherText));

        //RECEIVER
        System.out.println("\nRECEIVER");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        //Decrypting the text

        System.out.println("---------Decrypted K-(H(m))---------");
        byte[] decipheredText = cipher.doFinal(cipherText);
        System.out.println(bytesToHex(decipheredText));

        digest = MessageDigest.getInstance("SHA-256");
        encodedhash = digest.digest(
                originalString.getBytes(StandardCharsets.UTF_8));

        System.out.println("\n---------Hash(text)---------");
        System.out.println(bytesToHex(encodedhash));




    }
// convert to bytes to hex
    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

public static class SymmetricKey {

        public static SecretKey createAESKey(int keySize) throws Exception {
            SecureRandom securerandom = new SecureRandom();
            KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
            keygenerator.init(keySize, securerandom);
            return keygenerator.generateKey();
        }
    }


}