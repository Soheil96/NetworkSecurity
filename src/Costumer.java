public class Costumer implements Runnable {
    private Thread t;
    private String name;
    private Merchant merchant;


    @Override
    public void run() {
        System.out.println("Costumer " + name + " is online!");
    }

    Costumer(String s){
        name = s;
    }
    
    public void start(){
        if (t == null) {
            t = new Thread (this, "Costumer" + name);
            t.start ();
        }
    }
}
