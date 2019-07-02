import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.sql.Timestamp;
import java.util.concurrent.TimeUnit;

public class Costumer implements Runnable {
    private Thread t;
    private String name;
    private String trueUserID;
    private String userID;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private Netbill netbill;
    private String kticket;
    private String netbillTicket;
    private String groupTicket;
    private SecretKey netbillKey;
    private SecretKey sessionKey;
    private SecretKey groupKey;
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
            keyGen.initialize(1024, new SecureRandom(trueUserID.getBytes(StandardCharsets.UTF_8)));
            rsaKey = keyGen.genKeyPair();
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


    public void addGroup(Group group) throws Exception {
        ArrayList<String> details = group.addMember(this);
        groupTicket = details.get(0);
        byte[] decodedKey = Base64.getDecoder().decode(details.get(1));
        groupKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
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
        trueUserID = info.get(1);
        netbillTicket = info.get(2);
        byte[] decodedKey = Base64.getDecoder().decode(info.get(3));
        netbillKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }


    public void decryptProduct(ArrayList<String> receipt) throws Exception {
        if (receipt == null) {
            System.out.println(name + " : Transaction Failed!");
            return;
        }
        receipt = new SecFunctions().decrypt(receipt, null, sessionKey, "AES");
        byte[] decodedKey = Base64.getDecoder().decode(receipt.get(0));
        SecretKey productKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        String product = new SecFunctions().decrypt(new ArrayList<String>(Arrays.asList(encryptedProduct)), null, productKey, "AES").get(0);
        System.out.println(name + " : Mission completed!");
        System.out.println(product);
    }


    /**
     * It creates a payment order and signs it
     * @param merchant
     * @param EPOID
     */
    private void signPayment(Merchant merchant, ArrayList<String> EPOID, ArrayList<String> EPO) throws Exception {
        EPO.add(userID);
        EPO.add(merchant.getKerberosP().toString());
        ArrayList<String> acc = new ArrayList<String>();
        acc.add(account);
        acc.add(accountNonce);
        EPO.add(new SecFunctions().cryptographicChecksum(acc));
        EPO.addAll(EPOID);

        EPO.add(netbillTicket);
        acc.add(trueUserID);
        System.out.println(name + " : Product received! comment on the payment?");
        Scanner scanner = new Scanner(System.in);
        acc.add(scanner.nextLine());
        acc = new SecFunctions().encrypt(acc, null, netbillKey, "AES");
        EPO.addAll(acc);

        EPO.add(new SecFunctions().sign(EPO, rsaKey.getPrivate()));
        EPO = new SecFunctions().encrypt(EPO, null, sessionKey, "AES");
        EPO.add(kticket);
        decryptProduct(merchant.payment(this, EPO));
    }


    /**
     * It gets the product from the merchant and validates it
     * @param merchant
     * @param tid
     * @throws Exception
     */
    private void acceptOffer(Merchant merchant, int tid, ArrayList<String> EPO) throws Exception {
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
        String goodChecksum = request.get(request.size() - 1);
        if (!checksum.equals(goodChecksum))
            System.out.println(name + " : Checksum failed!");
        else {
            EPO.add(goodChecksum);
            request.remove(request.size() - 1);
            signPayment(merchant, request, EPO);
        }
    }


    /**
     * This function indicates the purchase will still in the price negotiation phase or will go to the delivery phase
     * @param merchant
     * @param tid
     * @param details is the reply from the merchant
     * @param EPO
     * @throws Exception
     */
    private void decidePurchase(Merchant merchant, int tid, ArrayList<String> details, ArrayList<String> EPO, Group group) throws Exception{
        if (details == null) {
            System.out.println(name + " : Ticket not valid or expired!");
            return;
        }
        details = new SecFunctions().decrypt(details, null, sessionKey, "AES");
        if (details.get(2).equals("1")) {
            System.out.println(name + " : The merchant doesn't have the product " + EPO.get(0) + "!");
            return;
        }

        System.out.println(name + " : Merchant's suggested price for the product " + EPO.get(0) + " is " + details.get(1));
        Scanner scanner = new Scanner(System.in);
        System.out.println("Accept or Deny or NewOffer?");
        String ans = scanner.next();
        if (ans.equals("Deny"))
            return;
        if (ans.equals("Accept")) {
            EPO.add(new SecFunctions().cryptographicChecksum(EPO));
            EPO.add(details.get(1));
            acceptOffer(merchant, tid, EPO);
            return;
        }
        System.out.println("New price offer: ");
        startPurchase(merchant, EPO.get(0), scanner.nextInt(), tid + 1, 0, group);
    }


    /**
     * initiates the first contact between the costumer and the merchant
     * @param merchant
     * @param pName
     * @param bid
     * @param tid
     * @param type 0 means true identity and 1 means pseudonym
     * @throws Exception
     */
    public void startPurchase(Merchant merchant, String pName, int bid, int tid, int type, Group group) throws Exception{
        if (tid == 0) {
            ArrayList<String> keyTicket = getSessionKey(merchant, type);
            if (keyTicket == null) {
                System.out.println(name + " : The signature rejected by the merchant!");
                return;
            }
            byte[] decodedKey = Base64.getDecoder().decode(keyTicket.get(0));
            sessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            kticket = keyTicket.get(1);
        }

        ArrayList<String> request = new ArrayList<String>();
        request.add(userID);
        request.add(pName);
        request.add(String.valueOf(bid));
        request.add("0");
        request.add(String.valueOf(tid));
        request = new SecFunctions().encrypt(request, null, sessionKey, "AES");
        request.add(kticket);

        ArrayList<String> answer = null;
        if (group == null) {
            answer = merchant.askPrice(this, request, null, null);
        } else {
            ArrayList<String>greq = new ArrayList<String>();
            greq.add(group.toString());
            greq.add(account);
            greq.add(userID);
            greq = new SecFunctions().encrypt(greq, null, groupKey, "AES");
            answer = merchant.askPrice(this, request, group.getSignature(groupTicket, greq), group);
        }
        request.clear();
        request.add(pName);
        decidePurchase(merchant, tid, answer, request, group);
    }


    /**
     * Contacts the merchant to get session key before initiating the purchase process
     * @param merchant
     * @param type 0 means true identity and 1 means pseudonym
     * @return
     * @throws Exception
     */
    private ArrayList<String> getSessionKey(Merchant merchant, int type) throws Exception{
        ArrayList<String> request = new ArrayList<String>();
        if (type == 1) {
            ArrayList<String> preq = new ArrayList<String>();
            preq.add(trueUserID);
            preq.add(String.valueOf(new Timestamp(new Date().getTime())));
            preq = new SecFunctions().encrypt(preq, null, netbillKey, "AES");
            preq.add(new SecFunctions().sign(preq, rsaKey.getPrivate()));
            preq.add(netbillTicket);
            preq = netbill.getPseudonym(merchant, preq);
            userID = preq.get(5);
            request.add(preq.get(3));
        } else {
            userID = trueUserID;
            request.add(userID);
        }

        request.add(merchant.toString());
        request.add(String.valueOf(new Timestamp(new Date().getTime())));
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        request.add(encodedKey);

        request = new SecFunctions().encrypt(request, merchant.getPK(), null, "RSA");
        request.add(new SecFunctions().sign(request, rsaKey.getPrivate()));
        ArrayList<String> answer = merchant.getTicket(this, request);
        return new SecFunctions().decrypt(answer, null, key, "AES");
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
        details.add(trueUserID);
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


    public String toString() {
        return "Costumer " + this.name;
    }
}
