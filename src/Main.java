public class Main {

    public static void main(String[] args) {
        Costumer c1 = new Costumer("c1");
        Merchant m1 = new Merchant("m1");
        Netbill n1 = new Netbill("n1");
        m1.start();
        c1.start();
        n1.start();
    }
}