$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"
$candidates = @(
    "root", "root123", "root@123", "Root@123", "Root123",
    "Admin@123", "admin123", "admin@123", "Admin123",
    "password", "Password@123", "Password123",
    "system", "tiger", "scott", "manager",
    "1234", "12345", "123456", "1234567", "12345678", "123456789", "0000",
    "cybertrace", "Cybertrace", "Cybertrace123", "Cybertrace@123",
    "dishant", "Dishant", "dishant123", "Dishant123", "Dishant@123", "dishant@123",
    "disha", "Disha", "disha123", "Disha123", "Disha@123", "disha@123",
    "dandade", "Dandade", "dandade123", "Dandade123", "Dandade@123"
)

foreach ($p in $candidates) {
    & $mysql -u root "-p$p" -e "SELECT 1;" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "FOUND MATCH: $p"
        exit 0
    }
}
Write-Host "No match found in candidate list."
