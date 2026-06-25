package com.example;

import java.util.Optional;

/**
 * REST controller for user profile endpoints.
 *
 * CORPUS FIXTURE — intentionally vulnerable.
 * CWE-639: IDOR planted in getProfile().
 */
public class Controller {

    private final UserRepository users = new UserRepository();

    /**
     * Return the profile for the given user id.
     *
     * SAST target: the caller-supplied {@code id} is used directly to fetch
     * any user record with no ownership or authorisation check — CWE-639
     * Insecure Direct Object Reference (broken access control).
     */
    public String getProfile(String id) throws Exception {
        // SAST target: IDOR / broken access control — CWE-639
        // No session check, no ownership verification — any id is accepted.
        int userId = Integer.parseInt(id);
        Optional<String> user = users.findById(userId);
        return user.orElse("not found");
    }
}
