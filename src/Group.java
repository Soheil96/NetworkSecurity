import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.Timestamp;
import java.util.*;

public class Group {
    private ArrayList<Costumer> members = new ArrayList<Costumer>();
    private KerberosPrincipal kp;
    private Map<String, SecretKey> keys = new HashMap<String, SecretKey>();
    private String name;
    private KeyPair rsaKey;


    Group(String name) {
        kp = new KerberosPrincipal(name+"@Group.com");
        this.name = name;
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, new SecureRandom());
            rsaKey = keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    public ArrayList<String> addMember(Costumer costumer) throws Exception {
        members.add(costumer);
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        KerberosTicket ticket = new SecFunctions().getKerberosTicket(costumer.getKerberosP(), this.kp, new Date());
        keys.put(ticket.toString(), key);
        ArrayList<String> request = new ArrayList<String>();
        request.add(ticket.toString());
        request.add(String.valueOf(Base64.getEncoder().encodeToString(key.getEncoded())));
        return request;
    }


    public ArrayList<String> getSignature(String ticket, ArrayList<String> request) throws Exception {
        request = new SecFunctions().decrypt(request, null, keys.get(ticket), "AES");
        request.add(String.valueOf(new Timestamp(new Date().getTime())));
        request.add(new SecFunctions().sign(request, rsaKey.getPrivate()));
        return request;
    }


    public PublicKey getPK() {
        return rsaKey.getPublic();
    }


    public String toString() {
        return "Group " + this.name;
    }
}
