import java.security.*;
import java.util.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.*;

public class Netbill implements Runnable{
    private Thread t;
    private String name;
    private KeyPair rsaKey;
    private KerberosPrincipal kerberosP;
    private int userNumber = 1402;
    private Map<String, Account> accounts = new HashMap<String, Account>();
    private Map<String, SecretKey> keys = new HashMap<String, SecretKey>();


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
     * TODO save information
     * @param nonce
     * @param encodedKey
     * @return
     * @throws Exception
     */
    public ArrayList<String> register(KerberosPrincipal kp, String nonce, ArrayList<String> encodedKey) throws Exception {
        encodedKey = new SecFunctions().decrypt(encodedKey, rsaKey.getPrivate(), null, "RSA");
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey.get(0));
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        ArrayList<String> request = new ArrayList<String>();
        Random rand = new Random();
        request.add(String.valueOf(rand.nextInt(100000000) + 100000000));
        request.add(String.valueOf(userNumber));
        userNumber += 1;
        KerberosTicket ticket = new SecFunctions().getKerberosTicket(kp, kerberosP, new Date());
        request.add(ticket.toString());
        SecretKey seskey = KeyGenerator.getInstance("AES").generateKey();
        request.add(String.valueOf(Base64.getEncoder().encodeToString(seskey.getEncoded())));

        Account account = new Account();
        account.kp = kp;
        account.nonce = nonce;
        account.user = request.get(1);
        account.value = 0;
        accounts.put(request.get(0), account);
        keys.put(request.get(2), seskey);
        return new SecFunctions().encrypt(request, null, key, "AES");
    }


    /**
     * It's for depositing and withdrawing from netbill account to bank account
     * @param ticket
     * @param request
     * @param type 0 means deposit and 1 means withdraw
     * @throws Exception
     */
    public boolean depositWithdraw(String ticket, ArrayList<String> request, int type) throws Exception {
        if (keys.get(ticket) == null)
            return false;
        request = new SecFunctions().decrypt(request, null, keys.get(ticket), "AES");
        if (accounts.get(request.get(0)) == null)
            return false;
        Account account = accounts.get(request.get(0));
        if (!account.user.equals(request.get(1)) || !account.nonce.equals(request.get(2)))
            return false;

        if (type == 0)
            account.value += Integer.parseInt(request.get(3));
        else
            account.value -= Integer.parseInt(request.get(3));
        return true;
    }


    public void transaction(Merchant merchant, ArrayList<String> EPO) {

    }
}


class Account {
    KerberosPrincipal kp;
    int value;
    String user;
    String nonce;
}