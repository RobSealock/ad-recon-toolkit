function Get-AzToken {
	<#
	.DESCRIPTION
	Get's Access Token for Service Principle using clientId and secret
	.PARAMETER clientId
	List of node ids to update
	.PARAMETER tenantId
	Use -Tier0 to toggle true, leave out for false
	.PARAMETER secret
	App secret for registered app in Azure tenant
	.EXAMPLE
	PS> Get-AzToken -clientId {Application/Client ID} -tenantId {Tenant ID} -secret {Application Secret}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$clientId,

		[Parameter(Position = 1, Mandatory = $true)]
		[string]$tenantId,

		[Parameter(Position = 2, Mandatory = $true)]
		[string]$secret
	)

	$AccessTokenParams = @{
		Method = 'POST'
		Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
		Body   = @{
			client_id     = $clientId
			scope         = 'https://graph.microsoft.com/.default'
			client_secret = $secret
			grant_type    = 'client_credentials'
		}
	}

	$AccessToken = Invoke-RestMethod @AccessTokenParams

	return $AccessToken.access_token
}

function New-AZUser {
	<#
	.DESCRIPTION
	Creates a new user to Azure tenant. Requires access token. Returns thew newly created user object.
	.PARAMETER displayName
	Display Name for new user
	.PARAMETER domain
	Domain for the new user
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> New-AZUser -displayName 'test1234' -domain '4144.microsoft.com' -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		[string]$domain,

		[Parameter(Position = 2, Mandatory = $true)]
		$token
	)

	$apiUrl = 'https://graph.microsoft.com/v1.0/users'

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'accountEnabled'    = $true
		'displayName'       = "$displayName"
		'mailNickname'      = "$displayName"
		'userPrincipalName' = "$displayName@$domain"
		'passwordProfile'   = @{
			'password'                      = 'Password1234!!'
			'forceChangePasswordNextSignIn' = $false
		}
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	return $response
}

function New-AZGroup {
	<#
	.DESCRIPTION
	Creates a group user to Azure tenant. Requires access token. Returns thew newly created group object.
	.PARAMETER displayName
	Display Name for new group
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> New-AZGroup -displayName 'test group 1234' -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		$token,
		[switch]$IsAssignableToRole,
		[Parameter(Position = 2, Mandatory = $false)]
		$mailEnabled = $true,
		[Parameter(Position = 3, Mandatory = $false)]
		$groupTypes = @('Unified'),
		[Parameter(Position = 4, Mandatory = $false)]
		$securityEnabled = $true       

	)

	$apiUrl = 'https://graph.microsoft.com/v1.0/groups'

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'displayName'        = "$displayName"
		'groupTypes'         = @(
			$groupTypes
		)
		'mailEnabled'        = $mailEnabled
		'mailNickname'       = $displayName.Replace(' ', '_')
		'securityEnabled'    = $securityEnabled
		'isAssignableToRole' = $IsAssignableToRole.ToString()
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	return $response
}

function New-AZDynamicGroup {
	<#
	.DESCRIPTION
	Creates a group user to Azure tenant. Requires access token. Returns thew newly created group object.
	.PARAMETER displayName
	Display Name for new group
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> New-AZUser -displayName 'test group 1234' -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		$token,
		
		[Parameter(Position = 2, Mandatory = $false)]
		$mailEnabled = $true,      
		
		[Parameter(Position = 3, Mandatory = $false)]
		$securityEnabled = $true,
        
		[Parameter(Position = 4, Mandatory = $false)]
		[string[]]$groupTypes = @('Unified', 'DynamicMembership')
        

	)

	$apiUrl = 'https://graph.microsoft.com/v1.0/groups'

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'displayName'                   = "$displayName"
		'groupTypes'                    = @(
			$groupTypes
		)
		'mailEnabled'                   = $mailEnabled
		'mailNickname'                  = $displayName.Replace(' ', '_')
		'securityEnabled'               = $securityEnabled		
		'membershipRule'                = "(user.displayName -startsWith `"#test#@`")"
		'membershipRuleProcessingState' = 'On'

	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	return $response
}

function New-AZApplication {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$displayName,
		[Parameter(Position = 1, Mandatory = $true)]
		$token,
		[switch]$LockEnabled,
		[switch]$AllProperties,
		[switch]$CredsWithUsageVerify
	)
	$apiUrl = 'https://graph.microsoft.com/beta/applications'

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'displayName'                       = "$displayName"
		'servicePrincipalLockConfiguration' = @{
			'isEnabled'                  = $LockEnabled.ToString()
			'allProperties'              = $AllProperties.ToString()
			'credentialsWithUsageVerify' = $CredsWithUsageVerify.ToString()
			'credentialsWithUsageSign'   = $false
			'identifierUris'             = $false
			'tokenEncryptionKeyId'       = $false
		}
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	return $response
}

function New-AZServicePrincipal {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$appId,
		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)
	$apiUrl = 'https://graph.microsoft.com/beta/servicePrincipals'

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'appId' = "$appId"
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	return $response
}

function Add-AZGroupMember {
	<#
	.DESCRIPTION
	Adds a user to a group in azure
	.PARAMETER groupId
	Id of the group
	.PARAMETER userId
	Id of the user
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> Add-AZGroupMember -groupId {group_id} -userId {user_id} -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$groupId,

		[Parameter(Position = 1, Mandatory = $true)]
		[string]$userId,

		[Parameter(Position = 2, Mandatory = $true)]
		$token
	)

	$apiUrl = "https://graph.microsoft.com/v1.0/groups/$groupId/members/`$ref"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	Invoke-RestMethod -UseBasicParsing @params
}

function Add-AZRoleMember {
	<#
	.DESCRIPTION
	Adds a user to a role in azure
	.PARAMETER roleId
	Id of the role (not role template id)
	.PARAMETER userId
	Id of the user
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> Add-AZRoleMember -roleId {role_id} -userId {user_id} -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$roleId,

		[Parameter(Position = 1, Mandatory = $true)]
		[string]$userId,

		[Parameter(Position = 2, Mandatory = $true)]
		$token
	)

	$apiUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members/`$ref"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$userId"
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	Invoke-RestMethod -UseBasicParsing @params
}

function Add-AZMGAppRoleAssignment {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$servicePrincipalId,
		[Parameter(Position = 1, Mandatory = $true)]
		[string]$appRoleName,
		[Parameter(Position = 2, Mandatory = $true)]
		$token
	)

	$graphService = (Get-AZServicePrincipal -displayName 'Microsoft Graph' -token $token).id
	$role = (Get-AZMGRole -appRoleName $appRoleName -token $token).id

	$apiUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$graphService/appRoleAssignments"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'principalId' = "$servicePrincipalId"
		'resourceId'  = "$graphService"
		'appRoleId'   = "$role"
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Post'
	}

	Invoke-RestMethod -UseBasicParsing @params
}

function Get-AZUser {
	<#
	.DESCRIPTION
	Searches for user by displayName and returns the user object
	.PARAMETER displayName
	Display Name of the user
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> Get-AZUser -displayName ('test1234') -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)

	$apiUrl = "https://graph.microsoft.com/v1.0/users?`$filter=displayName eq '$displayName'"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Get'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	# Process the response
	if ($response) {
		Write-Output 'Found user'
	}
    else {
		Write-Output 'Failed to find user.'
	}
	return $response.value
}


function Get-AZGroup {
	<#
	.DESCRIPTION
	Searches for group by displayName and returns the group object
	.PARAMETER displayName
	Display Name of the group
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> Get-AZGroup -displayName ('test group 1234') -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)

	$apiUrl = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$displayName'"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Get'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	# Process the response
	if ($response) {
		Write-Output 'Found group'
	}
 else {
		Write-Output 'Failed to find group.'
	}
	return $response.value
}

function Get-AZApplication {
	<#
	.DESCRIPTION
	Searches for application by displayName and returns the application object
	.PARAMETER displayName
	Display Name of the application
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> Get-AZApplication -displayName ('test app 1234') -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)

	$apiUrl = "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$displayName'"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Get'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	# Process the response
	if ($response) {
		Write-Output 'Found application'
	}
 else {
		Write-Output 'Failed to find application.'
	}
	return $response.value
}

function Get-AZRole {
	<#
	.DESCRIPTION
	Searches for a role by displayName and returns the role object
	.PARAMETER displayName
	Display Name of the role
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> Get-AZRole -displayName ('Global Administrator') -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)

	$apiUrl = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=displayName eq '$displayName'"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Get'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	# Process the response
	if ($response) {
		Write-Output 'Found role'
	}
 else {
		Write-Output 'Failed to find role.'
	}
	return $response.value
}

function Get-AZDomain {
	<#
	.DESCRIPTION
	Returns default domain name for tenant from which access token was retrieved
	.PARAMETER token
	Access Token
	.EXAMPLE
	PS> Get-AZDomain -token {access_token}
	#>
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$token
	)

	$apiUrl = 'https://graph.microsoft.com/v1.0/organization'

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Get'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params
	foreach ($domain in $response.value.verifiedDomains) {
		if ($domain.isDefault) {
			$defaultDomain = $domain.name
		}
	}
	return $defaultDomain
}

function Get-AZServicePrincipal {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[string]$displayName,

		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)

	$apiUrl = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$displayName'"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Get'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	# Process the response
	if ($response) {
		Write-Output 'Found role'
	}
 else {
		Write-Output 'Failed to find role.'
	}
	return $response.value
}

function Get-AZMGRole {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$appRoleName,
		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)

	$graphService = (Get-AZServicePrincipal -displayName 'Microsoft Graph' -token $token).id
	$apiUrl = "https://graph.microsoft.com/beta/servicePrincipals/$graphService/appRoles"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Get'
	}

	$response = Invoke-RestMethod -UseBasicParsing @params

	$role = $response.value | Where-Object { $_.value -eq "$appRoleName" }
	return $role
}

function Get-AZAllByType {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$objectType,
		[Parameter(Position = 1, Mandatory = $true)]
		$token
	)
	$apiUrl = "https://graph.microsoft.com/beta/$objectType/"

	while ($apiUrl) {
		$headers = @{
			'Authorization' = "Bearer $token"
			'Content-Type'  = 'application/json'
		}
		$params = @{
			Uri     = $apiUrl
			Headers = $headers
			Method  = 'Get'
		}

		$res = Invoke-RestMethod -UseBasicParsing @params

		$response = $response + $res.value
		$apiUrl = $res.'@odata.nextLink'
	}
	return $response
}

function Get-AZStatistics {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$token
	)

	$groups = (Get-AZAllByType -objectType 'groups' -token $token).Count
	$roles = (Get-AZAllByType -objectType 'directoryRoles' -token $token).Count
	$users = (Get-AZAllByType -objectType 'users' -token $token).Count
	$sps = (Get-AZAllByType -objectType 'servicePrincipals' -token $token).Count
	$apps = (Get-AZAllByType -objectType 'applications' -token $token).Count

	$statistics = @{
		groups = $groups
		roles  = $roles
		users  = $users
		sp     = $sps
		apps   = $apps
	}

	return $statistics
}
function Get-AZMultiTenantApps {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$token,
		[Parameter(Position = 1, Mandatory = $true)]
		$tenantId
	)
	$sps = (Get-AZAllByType -objectType 'servicePrincipals' -token $token)
	$nonTenantApps = ($sps | ? { $_.AppOwnerOrganizationId -ne "$tenantId" }).Count
	
	return $nonTenantApps
}

function Remove-AZMember {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		[ValidateSet('role', 'group')]
		$sourceType,
		[Parameter(Position = 1, Mandatory = $true)]
		$sourceId,
		[Parameter(Position = 2, Mandatory = $true)]
		$memberId,
		[Parameter(Position = 3, Mandatory = $true)]
		$token
	)
	if ($sourceType -eq 'role') {
		$source = 'directoryRoles'
	}
 else {
		$source = 'groups'
	}
	$apiUrl = "https://graph.microsoft.com/beta/$source/$sourceId/members/$memberId/`$ref"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Method  = 'Delete'
	}
	Invoke-RestMethod -UseBasicParsing @params
}

function Set-AZApplicationLockProperties {
	param(
		[Parameter(Position = 0, Mandatory = $true)]
		$id,
		[Parameter(Position = 1, Mandatory = $true)]
		$token,
		[switch]$IsEnabled,
		[switch]$AllProperties,
		[switch]$CredsWithUsageVerify
	)

	$apiUrl = "https://graph.microsoft.com/beta/applications/$id"

	$headers = @{
		'Authorization' = "Bearer $token"
		'Content-Type'  = 'application/json'
	}
	$body = @{
		'servicePrincipalLockConfiguration' = @{
			'isEnabled'                  = $IsEnabled.ToString()
			'allProperties'              = $AllProperties.ToString()
			'credentialsWithUsageVerify' = $CredsWithUsageVerify.ToString()
			'credentialsWithUsageSign'   = $false
			'identifierUris'             = $false
			'tokenEncryptionKeyId'       = $false
		}
	} | ConvertTo-Json

	$params = @{
		Uri     = $apiUrl
		Headers = $headers
		Body    = $body
		Method  = 'Patch'
	}

	Invoke-RestMethod -UseBasicParsing @params
}

function Create-AzRoleDefinition {
	param(
		[string]$accessToken,
		[string]$description,
		[string]$displayName,
		[bool]$isEnabled, 
		[string]$templateId = (New-Guid).Guid.ToString(),      
		[string[]]$allowedResourceActions
	)

	$url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'

	$body = @{
		description     = $description
		displayName     = $displayName
		isEnabled       = $isEnabled
		templateId      = $templateId
		rolePermissions = @(
			@{
				allowedResourceActions = $allowedResourceActions
			}
		)
	}

	$headers = @{
		Authorization  = "Bearer $accessToken"
		'Content-Type' = 'application/json'
	}

	try {
		$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 3) -ErrorAction Stop		
		Write-Host "Role Definition created successfully. Role Id: $($response.id)"
		return $response
	}
	catch {
		Write-Error "Error creating Role Definition: $($_.Exception.Message)"
	}
}

function Assign-AzRoleAssignment {
	param(
		[string]$accessToken,
		[string]$principalId,
		[string]$roleDefinitionId,
		[string]$directoryScopeId
	)

	$url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'

	$body = @{
		'@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
		principalId      = $principalId
		roleDefinitionId = $roleDefinitionId
		directoryScopeId = $directoryScopeId
	}

	$headers = @{
		Authorization  = "Bearer $accessToken"
		'Content-Type' = 'application/json'
	}

	try {
		$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 3) -ErrorAction Stop		
		Write-Host "Role Assignment created successfully. Assignment Id: $($response.id)"
		return $response
	}
	catch {
		Write-Error "Error creating Role Assignment: $($_.Exception.Message)"
	}

}

function Remove-AzRoleDefinition {
	param(
		[string]$accessToken,
		[string]$roleId
	)

	$url = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/$roleId"

	$headers = @{
		Authorization = "Bearer $accessToken"
	}

	try {
		Invoke-RestMethod -Uri $url -Method Delete -Headers $headers -ErrorAction Stop
		Write-Output "Role Definition with ID $roleId deleted successfully."
	}
	catch {
		Write-Error "Error deleting Role Definition: $($_.Exception.Message)"
	}
}

function Get-AZGraphByDisplayName {
	param(
		[string]$accessToken,
		[string]$displayName,
		[string]$objectClass
	)

	$url = "https://graph.microsoft.com/v1.0/$objectClass/"
	$filter = "?`$filter=displayname eq '$displayName'"
	$fullUrl = "$url$filter"

	$headers = @{
		Authorization = "Bearer $accessToken"
	}

	try {

		$group = Invoke-RestMethod -Uri $fullUrl -Method Get -Headers $headers -ErrorAction Stop
		if ($group.value.Count -eq 1) {
			Write-Output "Group found with display name '$displayName'. Group ID: $($group.value[0].id)"
			$group.value[0]
		}
		elseif ($group.value.Count -eq 0) {
			Write-Output "No groups found with display name '$displayName'."
		}
		else {
			Write-Output "Multiple groups found with display name '$displayName'. Unable to retrieve."
		}
	}
	catch {
		Write-Error "Error retrieving group: $($_.Exception.Message)"
	}
}

function Add-AzObjectAsOwner {
	param(
		[string]$targetId,
		[Parameter(Position = 0, Mandatory = $true)]
		[ValidateSet('servicePrincipal', 'user', 'application', 'group')]
		$sourceType,
		[Parameter(Position = 1, Mandatory = $true)]
		[ValidateSet('servicePrincipals', 'users', 'applications')]
		$targetType,
		$objectId,
		[string]$accessToken
	)
	if ($sourceType -eq 'user') {
		$source = 'users'
	}

	if ($sourceType -eq 'application') {
		$source = 'applications'
	} 
	if ($sourceType -eq 'group') {
		$source = 'groups'
	}

	if ($sourceType -eq 'servicePrincipal') {
		$source = 'servicePrincipals'
	}

	$url = "https://graph.microsoft.com/v1.0/$source/$targetId/owners/`$ref"
     
	$body = @{
		'@odata.id' = "https://graph.microsoft.com/v1.0/$targetType/$objectId"
	}

	$headers = @{
		Authorization  = "Bearer $accessToken"
		'Content-Type' = 'application/json'
	}

	$params = @{
		Uri         = $url
		Method      = 'Post'
		Headers     = $headers
		Body        = $body | ConvertTo-Json
		ErrorAction = 'Stop'
	}    
	try {
		$response = Invoke-RestMethod @params
		Write-Output 'User added as owner to the object successfully.'
	}
	catch {
		Write-Error "Error adding user as owner to the object: $($_.Exception.Message)"
	}
}       

function New-AzAdminUnit {
    param(
         [string]$accessToken,
	     [string]$displayName,
		 [switch]$isRestricted
    )

    $url = "https://graph.microsoft.com/beta/administrativeUnits"

    $body = @{
       
        displayName     = $displayName
        description     = $displayName
		isMemberManagementRestricted = $isRestricted.ToString()
		
    }

    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 3) -ErrorAction Stop
        Write-Host "Role Assignment created successfully. Assignment Id: $($response.id)"
		return $response
    }
    catch {
        Write-Error "Error creating Role Assignment: $($_.Exception.Message)"
    }

}
function Add-AzAdminUnitMember {
    param(
        [string]$accessToken,
        [string]$adminUnitObjectId,
        [string]$memberObjectId,
		[string]$objectType            
    )

    $url = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$adminUnitObjectId/members/`$ref"

    $body = @{
       
        '@odata.id' = "https://graph.microsoft.com/v1.0/$objectType/$memberObjectId"       
    }

    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 3) -ErrorAction Stop
        Write-Host "Role Assignment created successfully. Assignment Id: $($response.id)"
		return $response
    }
    catch {
        Write-Error "Error creating Role Assignment: $($_.Exception.Message)"
    }

}
