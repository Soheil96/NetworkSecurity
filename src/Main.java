import javax.security.auth.kerberos.*;
import java.util.concurrent.TimeUnit;

public class Main {

    public static void main(String[] args) throws Exception{
        /**
         * Setup phase
         */
        KerberosPrincipal kn1 = new KerberosPrincipal("n1@NETBILL.COM");
        Netbill n1 = new Netbill("n1", kn1);
        n1.start();
        KerberosPrincipal km1 = new KerberosPrincipal("m1@MERCHANT.COM");
        Merchant m1 = new Merchant("m1", km1, n1);
        m1.start();
        KerberosPrincipal km2 = new KerberosPrincipal("m2@MERCHANT.COM");
        Merchant m2 = new Merchant("m2", km2, n1);
        m2.start();
        KerberosPrincipal kc1 = new KerberosPrincipal("c1@COSTUMER.COM");
        Costumer c1 = new Costumer("c1", kc1, n1);
        c1.start();
        KerberosPrincipal kc2 = new KerberosPrincipal("c2@COSTUMER.COM");
        Costumer c2 = new Costumer("c2", kc2, n1);
        c2.start();

        n1.addMerchant(m1); n1.addMerchant(m2);
        m1.addProduct("p1", "product1");
        m1.addProduct("p2", "product2");


        /**
         * Purchase phase
         */
        TimeUnit.SECONDS.sleep(1);
        c1.startPurchase(m1, "p4", 100, 0);
        c1.startPurchase(m1, "p1", 100, 0);
    }
}