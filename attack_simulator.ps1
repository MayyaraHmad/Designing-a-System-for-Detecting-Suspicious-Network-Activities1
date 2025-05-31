# attack_simulator.ps1 - سكربت توليد هجمات تسجيل دخول وهمية (PowerShell)
# ينفذ 6 محاولات فاشلة ثم واحدة ناجحة باسم المستخدم محمود

for ($i=1; $i -le 6; $i++) {
    try {
        $u="Mahmood domi"
        $p=ConvertTo-SecureString "wrongpass" -AsPlainText -Force
        $c=New-Object System.Management.Automation.PSCredential ($u,$p)
        Start-Process -FilePath "cmd.exe" -Credential $c -ErrorAction Stop
    } catch {
        Write-Host "Failed attempt $i"
    }
}

try {
    $u="Mahmood domi"
    $p=ConvertTo-SecureString "159753" -AsPlainText -Force
    $c=New-Object System.Management.Automation.PSCredential ($u,$p)
    Start-Process -FilePath "cmd.exe" -Credential $c
} catch {
    Write-Host "Successful login failed"
}
