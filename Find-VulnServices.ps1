#
# Script to do a rough check for vulnerable installed services by looking for unquoted service paths or writable service paths
#

Write-Host " "

# Looking for services with unquoted paths
Write-Host "[+] Looking for services with unquoted paths"
Write-Host " "
$services = get-wmiobject -class win32_service | select displayname,name,state,pathname,startname,acceptstop
$unquotedservices = $services | where {$_.pathname -match ' ' -and $_.pathname -notmatch '"' -and $_.pathname -notmatch '-' -and $_.pathname -notmatch '/'}

# Printing the found unquotes service paths
if ($unquotedservices) {
	Write-Host "[+] Found the following services with unquoted paths:"
	Write-Host " "
	$unquotedservices | ft displayname,name,pathname
	Write-Host " "
} else {
	Write-Host "[!] Found no services with unquoted paths"
	Write-Host " "
}

# Looking for services with writable paths
Write-Host "[+] Looking for services with writable paths"
Write-Host " "
$writableservices = @()
foreach ($service in $services) {
	$exepath = ((($service.pathname -replace '"','') -split ' -')[0] -split ' /')[0]
	if ($exepath) {
		$dirpath = (get-item $exepath).psparentpath -split "::" | select -last 1
		if ($dirpath) {
			$useraccess = ($dirpath | get-acl).access | where {($_.identityreference -match "Users") -and ($_.filesystemrights -match "Modify" -or $_.filesystemrights -match "Write")}
			$adminaccess = ($dirpath | get-acl).access | where {($_.identityreference -match "Administrators") -and ($_.filesystemrights -match "Modify" -or $_.filesystemrights -match "Write")}
			if ($useraccess -or $adminaccess) {
				$obj = New-Object -TypeName PSObject
				Add-Member -InputObject $obj -MemberType NoteProperty -Name "DisplayName" -Value $service.displayname
				Add-Member -InputObject $obj -MemberType NoteProperty -Name "Name" -Value $service.name
				Add-Member -InputObject $obj -MemberType NoteProperty -Name "Path" -Value $dirpath
				if ($useraccess) {
					Add-Member -InputObject $obj -MemberType NoteProperty -Name "Access" -Value "Users"
				} else {
					Add-Member -InputObject $obj -MemberType NoteProperty -Name "Access" -Value "Administrators"
				}
				$writableservices += $obj
			}
		}
	}
}

# Printing the found writable service paths
if ($writableservices) {
	Write-Host "[+] Found the following services with writable paths:"
	$writableservices | ft
} else {
	Write-Host "[!] Found no services with writable paths"
	Write-Host " "
}

# Done
Write-Host "[+] Done!"
Write-Host " "
