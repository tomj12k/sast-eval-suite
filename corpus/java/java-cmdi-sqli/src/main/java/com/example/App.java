package com.example;

import java.sql.Connection;
import java.sql.Statement;

public class App {
    public String run(String host) throws Exception {
        // VULN: OS command injection via user-controlled host.
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }

    public void lookup(Connection conn, String user) throws Exception {
        Statement st = conn.createStatement();
        // VULN: SQL injection via string concatenation.
        st.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }
}
