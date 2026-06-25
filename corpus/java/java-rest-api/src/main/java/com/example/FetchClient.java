package com.example;

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * HTTP fetch helper used by the REST service.
 *
 * CORPUS FIXTURE — intentionally vulnerable.
 * CWE-918: SSRF planted in fetch().
 */
public class FetchClient {

    /**
     * Fetch the content at the given URL.
     *
     * SAST target: {@code url} is caller-supplied and passed directly to
     * {@code new URL(url).openStream()} with no allowlist or scheme check —
     * CWE-918 Server-Side Request Forgery.
     */
    public String fetch(String url) throws Exception {
        // SAST target: SSRF — CWE-918
        try (InputStream in = new URL(url).openStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
