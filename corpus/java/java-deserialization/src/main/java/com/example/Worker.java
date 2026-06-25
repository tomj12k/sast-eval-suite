package com.example;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class Worker {
    public Object handle(byte[] payload) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(payload));
        // VULN: deserializing untrusted bytes -> remote code execution.
        return in.readObject();
    }
}
