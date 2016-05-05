import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Date;
import java.util.Base64;


/**
 * Created by admin on 5/5/2016.
 */
public class CTF1 {
    public static void main(String[] args) throws Exception {

        // GET TOKEN
        String host = "dnegel-serv.com";
        int port = 80;
        String Cu64 = "";

        Socket s = new Socket(InetAddress.getByName(host), port);

        PrintWriter pw = new PrintWriter(s.getOutputStream());
        pw.println("GET /challenges/1/ HTTP/1.1");
        pw.println("Host: www.dnegel-serv.com");
        pw.println("Accept: */*");
        pw.println("User-Agent: Test");
        pw.println("");
        pw.flush();

        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String line;
        while((line = br.readLine()) != null){
            System.out.println(line);

            if(line.contains("Location")){
                Cu64 =  line.split("token=")[1];
                break;
            }
        }

        System.out.println(Cu64);  // END TOKEN

        byte[] cu = Base64.getDecoder().decode(Cu64);   // Encoding issue with special char


        // GET TIME
        int time = (int) (new Date().getTime() / 1000) + 10;
        System.out.println(time);


        byte[] pu = ("user=anonymous|ts="+time).getBytes();

        // Pu XOR Cu = Key
        byte[] key = new byte[cu.length];
        for (int i=0; i<cu.length; i++){
            key[i] = (byte) (cu[i] ^ pu[i]);
        }

        byte[] mPu = ("user=admin|ts="+time+"0000").getBytes();

        byte[] mCu = new byte[mPu.length];

        // Key XOR Padmin = mCu
        for(int i=0;i<mPu.length; i++){
            mCu[i] = (byte) (mPu[i] ^ key[i]);
        }

        String mCu64 = Base64.getEncoder().encodeToString(mCu);


        System.out.println(mCu64);
        pw.println("GET /challenges/1/?token="+mCu64+" HTTP/1.1");
        pw.println("Host: www.dnegel-serv.com");
        pw.println("Accept: */*");
        pw.println("User-Agent: Test");
        pw.println("");
        pw.flush();

        while((line = br.readLine()) != null){
            System.out.println(line);
        }

        br.close();
        pw.close();
    }
}
