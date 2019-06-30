import java.security.*;
import java.util.ArrayList;
import javax.security.auth.kerberos.*;

public class Netbill implements Runnable{
    private Thread t;
    private String name;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private ArrayList<Merchant> merchants = new ArrayList<Merchant>();
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


    public void addMerchant(Merchant m) {
        merchants.add(m);
    }


    public KerberosPrincipal getKerberosP() {
        return this.kerberosP;
    }


    public int signUp(Costumer c){
        costumers.add(c);
        return costumers.size() - 1;
    }


    public PublicKey getPK() {
        return rsaKey.getPublic();
    }


    public String toString() {
        return "Netbill " + this.name;
    }
}
