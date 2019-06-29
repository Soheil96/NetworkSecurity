import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

public class Costumer implements Runnable {
    private Thread t;
    private String name;
    private int userID;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private Netbill netbill;
    private String pticket;
    private SecretKey sessionKey;


    @Override
    public void run() {
        userID = netbill.signUp(this);
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            rsaKey = keyGen.genKeyPair();
            keyGen.initialize(1024, new SecureRandom(ByteBuffer.allocate(4).putInt(userID).array()));
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

    public KerberosPrincipal getKerberosP() {
        return this.kerberosP;
    }

    public PublicKey getPK() {
        return rsaKey.getPublic();
    }

    private void acceptOffer(Merchant merchant, int tid) {

    }

    /**
     * This function indicates the purchase will still in the price negotiation phase or will go to the delivery phase
     * @param merchant
     * @param pName
     * @param tid
     * @param details is the reply from the merchant
     * @throws Exception
     */
    private void decidePurchase(Merchant merchant, String pName, int tid, ArrayList<String> details) throws Exception{
        if (details == null) {
            System.out.println(name + " : The merchant doesn't have the product " + pName);
            return;
        }
        details = new SecFunctions().decrypt(details, null, sessionKey, "AES");
        System.out.println(name + " : Merchant's suggested price for the product " + pName + " is " + details.get(1));
        Scanner scanner = new Scanner(System.in);
        System.out.println("Accept or Deny or New Offer?");
        String ans = scanner.next();
        if (ans.equals("Deny"))
            return;
        if (ans.equals("Accept")) {
            acceptOffer(merchant, tid);
            return;
        }
        System.out.println("New price offer: ");
        startPurchase(merchant, pName, scanner.nextInt(), tid + 1);
    }

    /**
     * initiates the first contact between the costumer and the merchant
     * @param merchant
     * @param pName
     * @param bid
     * @param tid
     * @throws Exception
     */
    public void startPurchase(Merchant merchant, String pName, int bid, int tid) throws Exception{
        if (tid == 0) {
            ArrayList<String> keyTicket = getSessionKey(merchant);
            if (keyTicket == null) {
                System.out.println(name + " : The signature rejected by the merchant");
                return;
            }
            byte[] decodedKey = Base64.getDecoder().decode(keyTicket.get(0));
            sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            pticket = keyTicket.get(1);
        }
        ArrayList<String> request = new ArrayList<String>();
        request.add(this.name);
        request.add(pName);
        request.add(String.valueOf(bid));
        request.add("0");
        request.add(String.valueOf(tid));
        request = new SecFunctions().encrypt(request, null, sessionKey, "AES");
        ArrayList<String> answer = merchant.askPrice(this, pticket, request);
        decidePurchase(merchant, pName, tid, answer);
    }

    /**
     * Contacts the merchant to get session key before initiating the purchase process
     * @param merchant
     * @return
     * @throws Exception
     */
    private ArrayList<String> getSessionKey(Merchant merchant) throws Exception{
        ArrayList<String> request = new ArrayList<String>();
        request.add(String.valueOf(userID));
        request.add(merchant.toString());
        request.add(String.valueOf(new Timestamp(new Date().getTime())));
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        request.add(String.valueOf(encodedKey));
        request = new SecFunctions().encrypt(request, merchant.getPK(), null, "RSA");
        String signature = new SecFunctions().sign(request, rsaKey.getPrivate());
        ArrayList<String> answer = merchant.getTicket(this, request, signature);
        return new SecFunctions().decrypt(answer, null, key, "AES");
    }

    public String toString() {
        return "Costumer " + this.name;
    }
}
