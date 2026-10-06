// SPDX-License-Identifier: MIT
// V1250Client.java — run as the agent by test_v1250.sh (Java's InetAddress,
// through getaddrinfo and the Warden's stub).
//   java V1250Client <port> <wildcard-name> <outside-name>
import java.net.*;

public class V1250Client {
    public static void main(String[] a) throws Exception {
        String port = a[0], name = a[1], outside = a[2];
        long t0 = System.currentTimeMillis();
        try {
            System.out.println("OK resolve " + InetAddress.getByName(name).getHostAddress() + " " + (System.currentTimeMillis() - t0));
        } catch (Exception e) { System.out.println("ERR resolve " + (System.currentTimeMillis() - t0)); }
        t0 = System.currentTimeMillis();
        try {
            HttpURLConnection c = (HttpURLConnection) new URL("http://" + name + ":" + port + "/").openConnection(Proxy.NO_PROXY);
            c.setConnectTimeout(3000);
            System.out.println("OK http " + c.getResponseCode() + " " + (System.currentTimeMillis() - t0));
        } catch (Exception e) { System.out.println("ERR http " + (System.currentTimeMillis() - t0)); }
        t0 = System.currentTimeMillis();
        try { InetAddress.getByName(outside); System.out.println("OK unlisted " + (System.currentTimeMillis() - t0)); }
        catch (Exception e) { System.out.println("ERR unlisted " + (System.currentTimeMillis() - t0)); }
    }
}
