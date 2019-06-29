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
    private ArrayList<String> products = new ArrayList<String>();
    private ArrayList<String> productnames = new ArrayList<String>();
    private Map<Costumer, SecretKey> map = new HashMap<Costumer, SecretKey>();


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

    public void addProduct(String name, String product) {
        products.add(product);
        productnames.add(name);
    }

    /**
     * This function is called for the price request phase
     * @param ticket
     * @param details
     * @return
     * @throws Exception
     */
    public ArrayList<String> askPrice(Costumer costumer, String ticket, ArrayList<String> details) throws Exception{
        details = new SecFunctions().decrypt(details, null, map.get(costumer),"AES");
        ArrayList<String> request = new ArrayList<String>();
        request.add("Product name = " + details.get(1));
        request.add("0");
        request.add("0");
        request.add(details.get(4));

        boolean exists = false;
        for (String pName: productnames)
            if (pName.equals(details.get(1)))
                exists = true;
        if (exists == false)
            return null;

        Scanner scanner = new Scanner(System.in);
        System.out.println(name + " : A costumer requested product " + details.get(1) + " for the price of " + details.get(2));
        System.out.println("Suggested amount :");
        request.set(1, scanner.next());
        return new SecFunctions().encrypt(request, null, map.get(costumer),"AES");
    }

    /**
     * Creates ticket and a session key for the costumer before the purchase scenario starts
     * @param costumer
     * @param details
     * @param signature
     * @return
     * @throws Exception
     */
    public ArrayList<String> getTicket(Costumer costumer, ArrayList<String> details, String signature) throws Exception{
        if (new SecFunctions().verify(details, signature, costumer.getPK()) == false)
            return null;
        details = new SecFunctions().decrypt(details, rsaKey.getPrivate(), null, "RSA");
        byte[] decodedKey = Base64.getDecoder().decode(details.get(3));
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        KerberosTicket ticket = new SecFunctions().getKerberosTicket(costumer.getKerberosP(), kerberosP,
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(details.get(2)));
        SecretKey sessionKey = createSymmetricKey();
        map.put(costumer, sessionKey);
        ArrayList<String> request = new ArrayList<String>();
        request.add(String.valueOf(Base64.getEncoder().encodeToString(sessionKey.getEncoded())));
        request.add(String.valueOf(Base64.getEncoder().encodeToString(ticket.getEncoded())));
        return new SecFunctions().encrypt(request, null, key, "AES");
    }

    public String toString() {
        return "Merchant " + this.name;
    }
}
