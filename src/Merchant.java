public class Merchant implements Runnable {
    private Thread t;
    private String name;


    @Override
    public void run() {
        System.out.println("Merchant " + name + " is online!");
    }

    Merchant(String s){
        name = s;
    }

    public void start(){
        if (t == null) {
            t = new Thread (this, "Merchant" + name);
            t.start ();
        }
    }
}
