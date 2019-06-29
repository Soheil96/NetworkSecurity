import javax.security.auth.kerberos.*;
import java.security.*;

public class Costumer implements Runnable {
    private Thread t;
    private String name;
    private int userID;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private Netbill netbill;
    private Merchant merchant;


    @Override
    public void run() {
        userID = netbill.signUp(this);
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            rsaKey = keyGen.genKeyPair();
            keyGen.initialize(1024, new SecureRandom());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.out.println("Costumer " + name + " is online!");
    }

    Costumer(String s, KerberosPrincipal kp, Netbill n){
        netbill = n;
        kerberosP = kp;
        name = s;
    }
    
    public void start() {
        if (t == null) {
            t = new Thread (this, "Costumer" + name);
            t.start ();
        }
    }

    public void setMerchant(Merchant m) {
        merchant = m;
    }

    public KerberosPrincipal getKerberosP() {
        return this.kerberosP;
    }

    public PublicKey getPK() {
        return rsaKey.getPublic();
    }
}
