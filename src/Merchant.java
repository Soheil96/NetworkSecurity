import java.security.*;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.*;

public class Merchant implements Runnable {
    private Thread t;
    private String name;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private Netbill netbill;
    private Map<String, String> products = new HashMap<String, String>();
    private Map<Costumer, Profile> map = new HashMap<Costumer, Profile>();


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


    public void addProduct(String name, String product) {
        products.put(name, product);
    }


    /**
     * It sends EPOID and the encoded product for the costumer
     * @param costumer
     * @param details
     * @return
     */
    public ArrayList<String> goodDelivery(Costumer costumer, ArrayList<String> details) throws Exception {
        Profile costumerProfile = map.get(costumer);
        if (!costumerProfile.ticket.toString().equals(details.get(details.size() - 1)) ||
                costumerProfile.ticket.getEndTime().compareTo(new Date()) < 0)
            return null;
        details.remove(details.size() - 1);
        details = new SecFunctions().decrypt(details, null, costumerProfile.sessionKey, "AES");
        if (!details.get(0).equals(costumerProfile.tid)) {
            System.out.println(name + " : TID not exists!");
            return null;
        }

        ArrayList<String> request = new ArrayList<String>();
        request.add(this.toString());
        request.add(new Date().toString());
        Random rand = new Random();
        request.add(String.valueOf(rand.nextInt(Integer.MAX_VALUE)));
        costumerProfile.serialNumbers.add(request.get(request.size() - 1));

        ArrayList<String> good = new ArrayList<String>();
        good.add(products.get(costumerProfile.lastProduct));
        costumerProfile.productKey = createSymmetricKey();
        good = new SecFunctions().encrypt(good, null, costumerProfile.productKey, "AES");
        request.add(new SecFunctions().cryptographicChecksum(good));
        request = new SecFunctions().encrypt(request, null, costumerProfile.sessionKey, "AES");
        request.add(good.get(0));
        return request;
    }


    /**
     * Creates session key between the costumer and the merchant
     * @return
     */
    private SecretKey createSymmetricKey() {
        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generator.generateKey();
    }


    /**
     * This function is called for the price request phase
     * @param details
     * @return
     * @throws Exception
     */
    public ArrayList<String> askPrice(Costumer costumer, ArrayList<String> details) throws Exception{
        Profile costumerProfile = map.get(costumer);
        if (!costumerProfile.ticket.toString().equals(details.get(details.size() - 1)) ||
                costumerProfile.ticket.getEndTime().compareTo(new Date()) < 0)
            return null;
        details.remove(details.size() - 1);

        details = new SecFunctions().decrypt(details, null, costumerProfile.sessionKey,"AES");
        ArrayList<String> request = new ArrayList<String>();
        request.add("Product name = " + details.get(1));
        request.add("0");
        request.add("0");
        request.add(details.get(4));
        costumerProfile.lastProduct = details.get(1);
        if (products.get(details.get(1)) == null) {
            request.set(2, "1");
            return new SecFunctions().encrypt(request, null, costumerProfile.sessionKey, "AES");
        }

        Scanner scanner = new Scanner(System.in);
        System.out.println(name + " : A costumer requested product " + details.get(1) + " for the price of " + details.get(2));
        System.out.println("Suggested amount :");
        request.set(1, scanner.next());
        costumerProfile.lastPrice = request.get(1);
        costumerProfile.tid = request.get(3);
        return new SecFunctions().encrypt(request, null, costumerProfile.sessionKey, "AES");
    }


    /**
     * Creates ticket and a session key for the costumer before the purchase scenario starts
     * @param costumer
     * @param details
     * @return
     * @throws Exception
     */
    public ArrayList<String> getTicket(Costumer costumer, ArrayList<String> details) throws Exception{
        String signature = details.get(details.size() - 1);
        details.remove(details.size() - 1);
        if (!new SecFunctions().verify(details, signature, costumer.getPK()))
            return null;

        details = new SecFunctions().decrypt(details, rsaKey.getPrivate(), null, "RSA");
        byte[] decodedKey = Base64.getDecoder().decode(details.get(3));
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        KerberosTicket ticket = new SecFunctions().getKerberosTicket(costumer.getKerberosP(), kerberosP,
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(details.get(2)));
        SecretKey sessionKey = createSymmetricKey();

        if (map.get(costumer) == null)
            map.put(costumer, new Profile());
        map.get(costumer).ticket = ticket;
        map.get(costumer).sessionKey = sessionKey;

        ArrayList<String> request = new ArrayList<String>();
        request.add(String.valueOf(Base64.getEncoder().encodeToString(sessionKey.getEncoded())));
        request.add(ticket.toString());
        return new SecFunctions().encrypt(request, null, key, "AES");
    }


    public String toString() {
        return "Merchant " + this.name;
    }
}


class Profile {
    SecretKey sessionKey;
    SecretKey productKey;
    KerberosTicket ticket;
    ArrayList<String> serialNumbers = new ArrayList<String>();
    String username;
    String password;
    String tid;
    String lastPrice;
    String lastProduct;
}