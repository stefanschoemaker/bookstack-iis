[CmdletBinding()]
param (
  [String]$sitePath = "C:\inet\bookstack",
  [String]$UploadTempDir = "C:\inet\temp_dir"
)

## To-Dos
# 1. Fix php verbs to * you now have to manually go to the handler mappings and change the verbs to * for the php-cgi.exe


# Variables
$databaseName = "bookstack"
$dbUser = "bookstack_user"
$dbPassword = "secure_password"
$dbRootPassword = "root_password"
$serverName = ([System.Net.Dns]::GetHostByName($env:computerName)).HostName
$siteName = "BookStack_Site"
$envFilePath = "$sitePath\.env"
$phpExtensions = @("pdo_mysql", "mbstring", "ldap", "gd", "fileinfo")
$virtualDirectoryAlias = "bookstack"
$physicalPath = Join-Path $sitePath "public"
$caCertPath = 'C:\example\cert.crt'

##################### prerequisites install step

choco install php php-manager urlrewrite --s="https://community.chocolatey.org/api/v2" -y

$binary = php -r "echo PHP_BINARY;"
Write-Verbose "PHP binary path: $binary"
$phpPath = Split-Path $binary
Write-Verbose "PHP path: $phpPath"
$phpIniPath = Join-Path $phpPath "php.ini"
Write-Verbose "PHP ini path: $phpIniPath"
$phpExePath = Join-Path $phpPath "php-cgi.exe"
Write-Verbose "PHP exe path: $phpExePath"

# Update the php.ini file with the required settings

# Update or add the openssl.cafile directive
if ($caCertPath) {
  Write-Verbose "Certificate path provided: $caCertPath. Updating php.ini."
  try {
    (Get-Content $phpIniPath) -replace ';openssl.cafile=', "openssl.cafile=`"$caCertPath`"" | Set-Content $phpIniPath -ErrorAction Stop
    Write-Verbose "Updated openssl.cafile in php.ini."
  }
  catch {
    Write-Output "Failed to update openssl.cafile in php.ini."
    Write-Error $_.Exception.Message
  }

  # Update or add the curl.cainfo directive
  try {
    (Get-Content $phpIniPath) -replace ';curl.cainfo =', "curl.cainfo=`"$caCertPath`"" | Set-Content $phpIniPath -ErrorAction Stop
    Write-Verbose "Updated openssl.cafile in php.ini."
  }
  catch {
    Write-Output "Failed to update openssl.cafile in php.ini."
    Write-Error $_.Exception.Message
  }
}
else {
  Write-Output "No certificate path provided. Skipping updating php.ini."
}

# Update the upload_tmp_dir directive in php.ini
try {
  (Get-Content $phpIniPath) -replace ';upload_tmp_dir =', "upload_tmp_dir = `"$UploadTempDir`"" | Set-Content $phpIniPath -ErrorAction Stop
  Write-Verbose "Updated upload_tmp_dir in php.ini."
}
catch {
  Write-Output "Failed to update upload_tmp_dir in php.ini."
  Write-Error $_.Exception.Message
}

# End of editing php.ini file

choco install composer mariadb --s="https://community.chocolatey.org/api/v2" -y

Install-WindowsFeature -Name Web-Server, Web-Mgmt-Tools, Web-Security, Web-CGI

##################### End of prerequisites install step

# Add PHP
Add-PsSnapin PHPManagerSnapin
New-PHPVersion -ScriptProcessor $phpExePath

# Create Database and User
$sqlCommands = @"
CREATE DATABASE IF NOT EXISTS $databaseName;
CREATE USER IF NOT EXISTS '$dbUser'@'127.0.0.1' IDENTIFIED BY '$dbPassword';
CREATE USER IF NOT EXISTS '$dbUser'@'localhost' IDENTIFIED BY '$dbPassword';
CREATE USER IF NOT EXISTS '$dbUser'@'::1' IDENTIFIED BY '$dbPassword';
CREATE USER IF NOT EXISTS '$dbUser'@'$serverName' IDENTIFIED BY '$dbPassword';
GRANT ALL PRIVILEGES ON $databaseName.* TO '$dbUser'@'127.0.0.1';
GRANT ALL PRIVILEGES ON $databaseName.* TO '$dbUser'@'localhost';
GRANT ALL PRIVILEGES ON $databaseName.* TO '$dbUser'@'::1';
GRANT ALL PRIVILEGES ON $databaseName.* TO '$dbUser'@'$serverName';
FLUSH PRIVILEGES;
"@

# Execute SQL commands
Write-Output "Executing SQL commands to edit root password"
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$dbRootPassword';"
Write-Output "Executing SQL commands to create database and user"
mysql -u root -p"$dbRootPassword" -e "$sqlCommands"

# Download bookstack
Write-Output "Cloning BookStack repository from GitHub to C:\inet"
git clone https://github.com/BookStackApp/BookStack.git --branch release --single-branch $sitePath

# Import IIS module
Import-Module WebAdministration

# Create a new IIS site
New-Website -Name $siteName -PhysicalPath $sitePath -Port 80 -HostHeader $serverName -Force

$site = "IIS:\Sites\$siteName"

# Disable default document
Set-WebConfigurationProperty -filter "system.webserver/defaultdocument" -pspath $site -name "enabled" -Value "False"

# Create a self-signed certificate if not existing
$existing = Get-ChildItem -Path "cert:\LocalMachine\My" | Where-Object {
    ($_.DnsNameList -contains $serverName) -and ($_.EnhancedKeyUsageList.Friendlyname -contains "Server Authentication")
}

$cert = if ($null -eq $existing) {
  New-SelfSignedCertificate -DnsName $serverName -CertStoreLocation "cert:\LocalMachine\My"
}
else {
  $existing
}

# Get the existing web binding of the site for HTTPS
$binding = Get-WebBinding -Name $siteName -Protocol "https"

# If binding doesn't exist, create a new one
if ($null -eq $binding) {
  # Create a new HTTPS binding for the site
  New-WebBinding -Name $siteName -Protocol "https" -Port 443 -SslFlags 0 -HostHeader $serverName
  # Get the newly created binding
  $binding = Get-WebBinding -Name $siteName -Protocol "https"
}

$binding.AddSslCertificate($cert.Thumbprint, "my")


# Read the content of the php.ini file
$phpIniContent = Get-Content $phpIniPath

# Create a new list to hold the modified content
$modifiedContent = @()

# Flag to track if any changes were made
$changed = $false

foreach ($line in $phpIniContent) {
  $modified = $false
    
  foreach ($extension in $phpExtensions) {
    $enabledPattern = "^\s*extension\s*=\s*$extension\s*$"
    $commentedPattern = "^\s*;\s*extension\s*=\s*$extension\s*$"
        
    if ($line -match $enabledPattern) {
      # The extension is already enabled
      $modifiedContent += $line
      $modified = $true
      break
    }
    elseif ($line -match $commentedPattern) {
      # Uncomment the line to enable the extension
      $modifiedContent += $line -replace $commentedPattern, "extension=$extension"
      Write-Output "Uncommented the extension $extension."
      $changed = $true
      $modified = $true
      break
    }
  }

  if (-not $modified) {
    # Add the original line to the modified content if no modification was made
    $modifiedContent += $line
  }
}

# Add any missing extensions to the end of the file
foreach ($extension in $phpExtensions) {
  $enabledPattern = "^\s*extension\s*=\s*$extension\s*$"
  if (-not ($phpIniContent -match $enabledPattern)) {
    $modifiedContent += "extension=$extension"
    Write-Output "Added the extension $extension."
    $changed = $true
  }
}

# If changes were made, write the updated content back to the php.ini file
if ($changed) {
  $modifiedContent | Set-Content -Path $phpIniPath -Encoding utf8
  Write-Output "Updated $phpIniPath with the necessary extensions."
}
else {
  Write-Output "No changes were necessary; all extensions are already enabled."
}

# Navigate to the site directory
Set-Location $sitePath

# Install dependencies with Composer
Write-Verbose "Running composer config --global cafile $caCertPath"
composer config --global cafile "$caCertPath" --no-interaction
Write-Verbose "running composer install --no-dev"
composer install --no-dev --no-interaction

# Import the WebAdministration module if not already imported
Import-Module WebAdministration

# Check if the site exists
$site = Get-Website | Where-Object { $_.Name -eq $siteName }
if (-Not $site) {
  Write-Error "Site $siteName does not exist. Please check the site name."
  exit
}

# Check if the Virtual Directory already exists
$existingVD = Get-WebVirtualDirectory -Site $siteName -Name $virtualDirectoryAlias -ErrorAction SilentlyContinue

if ($existingVD) {
  Write-Verbose "Virtual Directory $virtualDirectoryAlias already exists under the site $siteName."
}
else {
  try {
    # Create the Virtual Directory
    New-WebVirtualDirectory -Site $siteName -Name $virtualDirectoryAlias -PhysicalPath $physicalPath -ErrorAction Stop
    Write-Verbose "Virtual Directory $virtualDirectoryAlias has been created under the site $siteName."
  }
  catch {
    Write-Error "Failed to create the Virtual Directory $virtualDirectoryAlias under the site $siteName."
    Write-Error $_.Exception.Message
  }
}

# Update the .env file
# Check if the .env file exists, and create it if it doesn't
if (-Not (Test-Path $envFilePath)) {
  Write-Verbose "Creating a new .env file at $envFilePath."
  Copy-Item "$($envFilePath).example" $envFilePath
}
else {}

# Modify the .env file
Write-Verbose "Modifying the .env file at $envFilePath."
$envContent = Get-Content $envFilePath
$envContent = $envContent -replace "APP_URL=.*", "APP_URL=https://$serverName/bookstack"
$envContent = $envContent -replace "DB_DATABASE=.*", "DB_DATABASE=$databaseName"
$envContent = $envContent -replace "DB_USERNAME=.*", "DB_USERNAME=$dbUser"
$envContent = $envContent -replace "DB_PASSWORD=.*", "DB_PASSWORD=$dbPassword"
$envContent | Set-Content $envFilePath

# Generate the application key
Write-Verbose "Generating the application key."
php artisan key:generate --force

# Run the migrations
Write-Verbose "Running the migrations."
php artisan migrate --force

# Get the current ACL for the directory
Write-Verbose "Setting permissions for IIS_IUSRS and Administrators on $sitePath."
$acl = Get-Acl $sitePath
# Create access rule for IIS_IUSRS group
$ruleIIS = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
# Add the access rule for IIS_IUSRS to the ACL
$acl.AddAccessRule($ruleIIS)
# Apply the updated ACL to the directory
try {
  Set-Acl -Path $sitePath -AclObject $acl -ErrorAction Stop
  Write-Verbose "Permissions for IIS_IUSRS have been set on $sitePath."
}
catch {
  Write-Error "Failed to set permissions for IIS_IUSRS on $sitePath."
  Write-Error $_.Exception.Message
}

# Define the paths as variables
$publicWebConfigPath = Join-Path $sitePath "public\web.config"
$rootWebConfigPath = Join-Path $sitePath "web.config"

# Define the content for the public web.config
$publicWebConfigContent = @"
<configuration>
  <system.webServer>
    <rewrite>
      <rewriteMaps>
        <rewriteMap name="{REQUEST_FILENAME}" />
      </rewriteMaps>
      <rules>
        <clear />
        <rule name="Rule 1" enabled="true" stopProcessing="true">
          <match url="^(.*)$" />
          <conditions logicalGrouping="MatchAll" trackAllCaptures="false">
            <add input="{R:1}" pattern="^(index\.php|images|css|js|favicon\.ico)" negate="true" />
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
            <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
          </conditions>
          <action type="Rewrite" url="./index.php/{R:1}" logRewrittenUrl="true" />
        </rule>
        <rule name="Rule 2" enabled="true" stopProcessing="true">
          <match url="^$" />
          <conditions logicalGrouping="MatchAll" trackAllCaptures="false">
            <add input="{URL}" pattern="(.*/bookstack)$" />
          </conditions>
          <action type="Redirect" url="index.php" />
        </rule>
        <rule name="Rewrite images gallery" stopProcessing="true">
          <match url="(^/*)(.*$)" />
          <conditions>
                        <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
                        <add input="{URL}" pattern="(\/images\/gallery)(.*)" />
          </conditions>
          <action type="Rewrite" url="/bookstack/index.php/uploads{C:0}" appendQueryString="true" logRewrittenUrl="true" />
        </rule>
        <rule name="Rule 3" enabled="true" stopProcessing="true">
          <match url="(^/*)(.*$)" ignoreCase="false" />
          <conditions logicalGrouping="MatchAll" trackAllCaptures="false">
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
            <add input="{R:0}" pattern="(index\\.php|images|css|js|favicon\.ico)" negate="true" />
          </conditions>
          <action type="Rewrite" url="index.php/{R:1}" logRewrittenUrl="true" />
        </rule>
      </rules>
    </rewrite>
    <directoryBrowse enabled="false" />
    <defaultDocument enabled="true">
      <files>
        <clear />
        <add value="index.php" />
        <add value="index" />
      </files>
    </defaultDocument>
  </system.webServer>
  <system.web>
    <customErrors mode="Detailed" />
  </system.web>
</configuration>
"@

# Define the content for the root web.config
$rootWebConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <clear />
                <rule name="Redirect to public" enabled="true" stopProcessing="true">
                    <match url="^bookstack(/.*)?$" />
                    <conditions>
                        <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
                        <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
                    </conditions>
                    <action type="Rewrite" url="/bookstack/public{R:1}" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
"@

# Overwrite the public web.config file
Write-Output "Writing to $publicWebConfigPath..."

try {
  $publicWebConfigContent | Out-File -FilePath $publicWebConfigPath -Encoding utf8 -Force -ErrorAction Stop
  Write-Output "Successfully wrote to $publicWebConfigPath."
}
catch {
  Write-Output "Failed to write to $publicWebConfigPath."
  Write-Error $_.Exception.Message
}

# Overwrite the root web.config file
Write-Output "Writing to $rootWebConfigPath..."
try {
  $rootWebConfigContent | Out-File -FilePath $rootWebConfigPath -Encoding utf8 -Force -ErrorAction Stop
  Write-Output "Successfully wrote to $rootWebConfigPath."
}
catch {
  Write-Output "Failed to write to $rootWebConfigPath."
  Write-Error $_.Exception.Message
}

# Reset IIS
iisreset

# Output completion message
Write-Host "BookStack installation and configuration completed. You can now access BookStack at https://$serverName/bookstack." -ForegroundColor Green
