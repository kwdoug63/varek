// SPDX-License-Identifier: MIT
// V1240Client.java — run as the agent by test_v1240.sh (Java's InetAddress).
import java.net.*;

public class V1240Client {
    public static void main(String[] a) throws Exception {
        String port = a[0];
        long t0 = System.currentTimeMillis();
        try {
            System.out.println("OK resolve " + InetAddress.getByName("api.example.com").getHostAddress() + " " + (System.currentTimeMillis() - t0));
        } catch (Exception e) { System.out.println("ERR resolve " + (System.currentTimeMillis() - t0)); }
        t0 = System.currentTimeMillis();
        try {
            HttpURLConnection c = (HttpURLConnection) new URL("http://api.example.com:" + port + "/").openConnection(Proxy.NO_PROXY);
            c.setConnectTimeout(3000);
            System.out.println("OK http " + c.getResponseCode() + " " + (System.currentTimeMillis() - t0));
        } catch (Exception e) { System.out.println("ERR http " + (System.currentTimeMillis() - t0)); }
        t0 = System.currentTimeMillis();
        try { InetAddress.getByName("other.example.com"); System.out.println("OK unlisted " + (System.currentTimeMillis() - t0)); }
        catch (Exception e) { System.out.println("ERR unlisted " + (System.currentTimeMillis() - t0)); }
    }
}
