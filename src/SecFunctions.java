import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.kerberos.*;
import java.awt.image.AreaAveragingScaleFilter;
import java.net.InetAddress;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.nio.charset.StandardCharsets;


public class SecFunctions {

    public KerberosTicket getKerberosTicket(KerberosPrincipal client, KerberosPrincipal server){
        return new KerberosTicket(
                new byte[0],
                client,
                server,
                new byte[0],
                0,
                new boolean[0],
                new Date(),
                new Date(),
                new Date(),
                new Date(),
                new InetAddress[0]);
    }

    /**
     * It does both symmetric and asymmetric encryption
     * For symmetric encryption, publicKey has to be null and algorithm has to "AES"
     * @param plainText is a list of Strings
     * @param pkey can be null
     * @param skey can be null
     * @param algorithm should be either "RSA" or "AES"
     * @return
     * @throws Exception
     */
    public ArrayList<String> encrypt(ArrayList<String> plainText, PublicKey pkey, SecretKey skey, String algorithm) throws Exception{
        ArrayList<String> cipherText = new ArrayList<String>();
        Cipher encryptCipher = Cipher.getInstance(algorithm);
        encryptCipher.init(Cipher.ENCRYPT_MODE, (algorithm == "AES" ? skey : pkey));
        for(String text : plainText){
            cipherText.add(Base64.getEncoder().encodeToString(encryptCipher.doFinal(text.getBytes(StandardCharsets.UTF_8))));
        }
        return cipherText;
    }

    /**
     * It does both symmetric and asymmetric decryption
     * For symmetric decryption, privateKey has to be null and algorithm has to "AES"
     * @param chiperText is a list of Strings
     * @param pkey can be null
     * @param skey can be null
     * @param algorithm should be either "RSA" or "AES"
     * @return
     * @throws Exception
     */
    public ArrayList<String> decrypt(ArrayList<String> chiperText, PrivateKey pkey, SecretKey skey, String algorithm) throws Exception{
        ArrayList<String> plainText = new ArrayList<String>();
        Cipher decryptCipher = Cipher.getInstance(algorithm);
        decryptCipher.init(Cipher.DECRYPT_MODE, (algorithm == "AES" ? skey : pkey));
        for(String text : chiperText){
            plainText.add(new String(decryptCipher.doFinal(Base64.getDecoder().decode(text)), StandardCharsets.UTF_8));
        }
        return plainText;
    }

    /**
     * It gets a list of strings and returns a DSA of their concatenation
     * @param plainText
     * @param key
     * @return
     * @throws Exception
     */
    public String sign(ArrayList<String> plainText, PrivateKey key) throws Exception {
        String text = "";
        for (String s: plainText) {
            text += s;
        }
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(key);
        privateSignature.update(text.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getEncoder().encodeToString(privateSignature.sign());
        return signature;
    }

    /**
     * It verifies a DSA on given list of strings
     * @param plainText
     * @param key
     * @return
     * @throws Exception
     */
    public boolean verify(ArrayList<String> plainText, String signature, PublicKey key) throws Exception {
        String text = "";
        for (String s: plainText) {
            text += s;
        }
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(key);
        publicSignature.update(text.getBytes(StandardCharsets.UTF_8));
        return publicSignature.verify(Base64.getDecoder().decode(signature));
    }

    public String cryptographicChecksum(ArrayList<String> plainText) throws Exception{
        String text = "";
        for (String s: plainText) {
            text += s;
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash = Base64.getEncoder().encodeToString(digest.digest(text.getBytes(StandardCharsets.UTF_8)));
        return hash;
    }
}
