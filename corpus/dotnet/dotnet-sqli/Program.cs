using Microsoft.Data.SqlClient;

public class Lookup
{
    public void Find(SqlConnection conn, string user)
    {
        // VULN: SQL injection via string concatenation.
        var sql = "SELECT * FROM users WHERE name = '" + user + "'";
        var cmd = new SqlCommand(sql, conn);
        cmd.ExecuteReader();
    }
}
