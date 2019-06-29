import java.security.*;
import java.util.ArrayList;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.kerberos.*;

public class Merchant implements Runnable {
    private Thread t;
    private String name;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private Netbill netbill;
    private ArrayList<Costumer> costumers = new ArrayList<Costumer>();


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
        System.out.println("Merchant " + name + " is online!");
    }

    Merchant(String s, KerberosPrincipal kp, Netbill n){
        name = s;
        kerberosP = kp;
        netbill = n;
    }

    private SecretKey createSymmetricKey() {
        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generator.generateKey();
    }

    public void start() {
        if (t == null) {
            t = new Thread (this, "Merchant" + name);
            t.start ();
        }
    }

    public KerberosPrincipal getKerberosP() {
        return this.kerberosP;
    }

    public PublicKey getPK() {
        return rsaKey.getPublic();
    }
}
