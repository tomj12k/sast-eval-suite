package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Optional;

/**
 * Thin database access layer for user records.
 *
 * CORPUS FIXTURE — intentionally vulnerable.
 * CWE-89: SQL injection planted in findByName().
 */
public class UserRepository {

    private Connection getConnection() throws Exception {
        return DriverManager.getConnection(AppConfig.DB_URL);
    }

    /**
     * Look up a user by name.
     *
     * SAST target: caller-supplied {@code name} is concatenated directly into
     * the SQL string — CWE-89 SQL injection.
     */
    public Optional<String> findByName(String name) throws Exception {
        // SAST target: SQL injection — CWE-89
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return Optional.of(rs.getString("name"));
            }
        }
        return Optional.empty();
    }

    /**
     * Look up a user by id using a safe parameterised query (not a SAST target).
     */
    public Optional<String> findById(int id) throws Exception {
        try (Connection conn = getConnection();
             var ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")) {
            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(rs.getString("name"));
                }
            }
        }
        return Optional.empty();
    }
}
