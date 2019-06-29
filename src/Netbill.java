public class Netbill implements Runnable{
    private Thread t;
    private String name;


    @Override
    public void run() {
        System.out.println("Netbill " + name + " is online!");
    }

    Netbill(String s){
        name = s;
    }

    public void start(){
        if (t == null) {
            t = new Thread (this, "Netbill" + name);
            t.start ();
        }
    }
}
