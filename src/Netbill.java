import java.security.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.*;

public class Netbill implements Runnable{
    private Thread t;
    private String name;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private int userNumber = 1402;


    @Override
    public void run() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            rsaKey = keyGen.genKeyPair();
            keyGen.initialize(1024, new SecureRandom());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.println("Netbill " + name + " is online!");
    }


    Netbill(String s, KerberosPrincipal kp){
        name = s;
        kerberosP = kp;
    }


    public void start() {
        if (t == null) {
            t = new Thread (this, "Netbill" + name);
            t.start ();
        }
    }


    public KerberosPrincipal getKerberosP() {
        return this.kerberosP;
    }


    public String getNonce() {
        Random rand = new Random();
        return String.valueOf(rand.nextInt(Integer.MAX_VALUE));
    }


    public PublicKey getPK() {
        return rsaKey.getPublic();
    }


    public String toString() {
        return "Netbill " + this.name;
    }


    /**
     * TODO add kerberos ticket and save information
     * TODO add merchant registration
     * @param nonce
     * @param encodedKey
     * @return
     * @throws Exception
     */
    public ArrayList<String> register(String nonce, ArrayList<String> encodedKey) throws Exception {
        encodedKey = new SecFunctions().decrypt(encodedKey, rsaKey.getPrivate(), null, "RSA");
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey.get(0));
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        ArrayList<String> request = new ArrayList<String>();
        Random rand = new Random();
        request.add(String.valueOf(rand.nextInt(100000000) + 100000000));
        request.add(String.valueOf(userNumber));
        userNumber += 1;
        return request;
    }
}
