import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

public class Costumer implements Runnable {
    private Thread t;
    private String name;
    private String userID;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private Netbill netbill;
    private String kticket;
    private String netbillTicket;
    private SecretKey netbillKey;
    private SecretKey sessionKey;
    private String encryptedProduct;
    private String account;
    private String accountNonce;


    @Override
    public void run() {
        KeyPairGenerator keyGen = null;
        try {
            TimeUnit.SECONDS.sleep(1);
            signUpAccount();
            keyGen = KeyPairGenerator.getInstance("RSA");
            rsaKey = keyGen.genKeyPair();
            keyGen.initialize(1024, new SecureRandom(userID.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (Exception e) {
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


    /**
     * It creates an account on Netbill server and shares a symmetric key with the netbill
     * @throws Exception
     */
    private void signUpAccount() throws Exception{
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        accountNonce = netbill.getNonce();
        ArrayList<String> keystr = new ArrayList<String>();
        keystr.add(String.valueOf(Base64.getEncoder().encodeToString(key.getEncoded())));

        ArrayList<String> info = netbill.register(kerberosP, accountNonce, new SecFunctions().encrypt(keystr, netbill.getPK(), null, "RSA"));
        info = new SecFunctions().decrypt(info, null, key, "AES");
        account = info.get(0);
        userID = info.get(1);
        netbillTicket = info.get(2);
        byte[] decodedKey = Base64.getDecoder().decode(info.get(3));
        netbillKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }


    /**
     * TODO
     * @param merchant
     * @param EPOID
     */
    private void signPayment(Merchant merchant, ArrayList<String> EPOID) {
        System.out.println("Product received!");
    }


    /**
     * It gets the product from the merchant and validates it
     * @param merchant
     * @param tid
     * @throws Exception
     */
    private void acceptOffer(Merchant merchant, int tid) throws Exception {
        ArrayList <String> request = new ArrayList<String>();
        request.add(String.valueOf(tid));
        request = new SecFunctions().encrypt(request, null, sessionKey, "AES");
        request.add(kticket);
        request = merchant.goodDelivery(this, request);
        if (request == null) {
            System.out.println(name + " : Ticket or TID not valid!");
            return;
        }

        encryptedProduct = request.get(request.size() - 1);
        request.remove(request.size() - 1);
        request = new SecFunctions().decrypt(request, null, sessionKey, "AES");
        ArrayList<String> good = new ArrayList<String>();
        good.add(encryptedProduct);
        String checksum = new SecFunctions().cryptographicChecksum(good);
        if (!checksum.equals(request.get(request.size() - 1)))
            System.out.println(name + " : Checksum failed!");
        else {
            request.remove(request.size() - 1);
            signPayment(merchant, request);
        }
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
            System.out.println(name + " : Ticket not valid or expired!");
            return;
        }
        details = new SecFunctions().decrypt(details, null, sessionKey, "AES");
        if (details.get(2).equals("1")) {
            System.out.println(name + " : The merchant doesn't have the product " + pName + "!");
            return;
        }

        System.out.println(name + " : Merchant's suggested price for the product " + pName + " is " + details.get(1));
        Scanner scanner = new Scanner(System.in);
        System.out.println("Accept or Deny or NewOffer?");
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
                System.out.println(name + " : The signature rejected by the merchant!");
                return;
            }
            byte[] decodedKey = Base64.getDecoder().decode(keyTicket.get(0));
            sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            kticket = keyTicket.get(1);
        }

        ArrayList<String> request = new ArrayList<String>();
        request.add(this.name);
        request.add(pName);
        request.add(String.valueOf(bid));
        request.add("0");
        request.add(String.valueOf(tid));
        request = new SecFunctions().encrypt(request, null, sessionKey, "AES");
        request.add(kticket);
        ArrayList<String> answer = merchant.askPrice(this, request);
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
        request.add(new SecFunctions().sign(request, rsaKey.getPrivate()));
        ArrayList<String> answer = merchant.getTicket(this, request);
        return new SecFunctions().decrypt(answer, null, key, "AES");
    }


    public String toString() {
        return "Costumer " + this.name;
    }


    /**
     * It's for depositing and withdrawing from netbill account to bank account
     * @param value
     * @param type 0 means deposit and 1 means withdraw
     * @throws Exception
     */
    public void depositWithdraw(int value, int type) throws Exception {
        ArrayList<String> details = new ArrayList<String>();
        details.add(account);
        details.add(userID);
        details.add(accountNonce);
        details.add(String.valueOf(value));
        details = new SecFunctions().encrypt(details, null, netbillKey, "AES");
        if (!netbill.depositWithdraw(netbillTicket, details, type)) {
            System.out.println(name + " : Transaction failed, credentials are wrong!");
            return;
        }
        if (type == 0)
            System.out.println(name + " : Deposit successful!");
        else
            System.out.println(name + " : Withdraw successful!");
    }
}
