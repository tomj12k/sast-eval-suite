package com.example;

/**
 * Application configuration.
 *
 * CORPUS FIXTURE — intentionally vulnerable.
 * CWE-798: hardcoded credential planted on the API_KEY field.
 */
public class AppConfig {

    // SAST target: hardcoded API key — CWE-798
    public static final String API_KEY = "hardcoded-api-key-do-not-use";

    public static final String DB_URL = "jdbc:h2:mem:testdb";

    private AppConfig() {}
}
