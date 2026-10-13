$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"
$passwords = @("dishant", "Dishant", "dishant123", "Dishant123", "Dishant@123", "dishant@123", "dishant30", "Dishant30", "Dishant@30", "dishant@30", "dishantdandade", "DishantDandade")

foreach ($p in $passwords) {
    & $mysql -u root "-p$p" -e "SELECT 1;" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "FOUND: $p"
        exit 0
    }
}
Write-Host "No match in personal list."
