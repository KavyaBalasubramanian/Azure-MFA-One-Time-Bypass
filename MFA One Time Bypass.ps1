Remove-Variable * -ErrorAction SilentlyContinue



$tenant = "xxxxxx"									  ############ Replace with your tenant GUID
$resource = "https://graph.microsoft.com/"
$authUrl = "https://login.microsoftonline.com/$tenant"
$endresult = $Null
$endresult = @()
$result = $Null
$InFinal = $False                                                                         ############# We are using this temp parameter to decide in the end if a CA policy has to be in the resultant #########################
$endcheck = $False                                                                        ############# This parameter to cut short the loop and come out to check other policies, by default we set this to False ##############
$TemplateId = $Null                                                                       ############# Used to convert User Role IDs to Role Template IDs which CA policies use #######################
$UserRoleTemplateIDs = @()                                                                ############# Array containing all the Role Template IDs the user is assigned to/part of##############################################








####### READ COMMENTS FROM HERE ############

############################################################################################################################################################
############################################################ Token Initialization ##########################################################################
############################################################################################################################################################

$clientId = "xxxxx"                                                                       #Client ID that you create for your tenant
$clientsecret = "xxxxx"                                                                   #Its Client secret
$redirectUri = "https://jwt.ms/”                                                          #App Registration’s Redirect URI

$postParams = @{resource = "$resource"; client_id = "$clientId"; client_secret = "$clientsecret"; grant_type = "client_credentials"}
$response = Invoke-RestMethod -Method POST -Uri "$authurl/oauth2/token" -Body $postParams


$accessToken = $response.access_token                                                     #The app registration on the Azure portal has been given group read all permissions, and User Read all permissions. 
                                                                                          #Without User.Read.All permissions, you cannot view the details of the members.


################################# User UPN Input #######################################


$User = Read-Host ("Please enter the UPN of the user `n ")                                ##Input UPN 






############################################################################################################################################################
################################################## Get Group IDs the user is a member of ###################################################################
############################################################################################################################################################


$UserGroupsURL = 'https://graph.microsoft.com/beta/users/' + $User + '/memberOf'                                                         ##Build URL for the graph query
$groupsRaw1 = Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $UserGroupsURL -Method GET           ## Get the raw response needed
$GroupsRaw2 = $groupsRaw1.Value                                                                                                          ## Capture value of the raw data
$Groups = $GroupsRaw2 | select id, DisplayName                                                                                           ## Filter out by DisplayName, GroupID


############################################################################################################################################################
############################### Get Roles of the user and convert it to RoleTemplateID values from their Directory##########################################
############################################################################################################################################################

$AllDirectoryRolesURL = 'https://graph.microsoft.com/beta/directoryroles/'                                                                              # Build URL for the graph query
$AllDirectoryRoles = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $AllDirectoryRolesURL -Method GET).value    # Get the raw response needed for all directory roles


    foreach ($r in $Groups) {                                                                                                                            ## The earlier Group output we pulled, has Role IDs in it as well. 
                                                                                                                                                        ## So we go through them and check if they are Roles 
            $Role = $AllDirectoryRoles | where id -eq $r.id
            $TemplateId = $Role | select roleTemplateId, displayName
          ##  Write-Host " $FinalTemplateIDs"                                                                                                           #### For Debugging purposes 
            $UserRoleTemplateIDs += $TemplateId                                                                                                         #### Making an array to make sure we can reference it later to compare
                                                                                                                                                        #### into Roles of CA policy ####
        }


############################################################################################################################################################
##########################################################Role Output for debug inforamtion################################################################
############################################################################################################################################################

Write-Host "Object ID                                     | Role Name"                                                                                  ######################### Output Roles for debug inforamtion #################
Write-Host "___________________________________________________________"                                                                                ######################### Output Roles for debug inforamtion #################

$UserRoleTemplateIDs | ForEach-Object {
    Write-Host "$($_.roletemplateID)          |  $($_.DisplayName)"
    }               

############################################################################################################################################################
################################################## Get User's Object ID to search in CA  ###################################################################
############################################################################################################################################################


$UserInfoURL = 'https://graph.microsoft.com/beta/users/' + $User                                                                                         ##Build URL for the graph query for user
$UserInfoRaw = Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $UserInfoURL -Method GET                            ## Get the raw response needed
$userObjectId = $userInforaw.id ## Store User Object ID








############################################################################################################################################################
##########################################################Group Output for debug inforamtion################################################################
############################################################################################################################################################

Write-Host "The user $user is part of the following group(s) `n"######################### Output Group for debug inforamtion #################
Write-Host "Object ID                                     | DisplayName"          ######################### Output Group for debug inforamtion #################
Write-Host "___________________________________________________________"          ######################### Output Group for debug inforamtion #################
Foreach ($a in $Groups)                                                           ######################### Output Group for debug inforamtion #################      #This can be removed
    {                                                                             ######################### Output Group for debug inforamtion #################
        $b = $a.DisplayName                                                       ######################### Output Group for debug inforamtion #################
        $c = $a.id                                                                ######################### Output Group for debug inforamtion #################
        Write-Host "$c          | $b"                                             ######################### Output Group for debug inforamtion #################
    }









############################################################################################################################################################
##################################### Get Enabled CA Policies from the tenant where MFA is a control########################################################
############################################################################################################################################################


Write-Host " `n `n Sending Graph query to get CA policies and its properties . . . . . . `n " 


$CAPoliciesURL = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
$CAPRaw1 = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $CAPoliciesURL -Method GET).value  ## Get the raw response needed
$CAPs = $CAPRaw1 | select id, DisplayName, state, grantControls, Conditions ## Filter our for needed attributes
$EnabledCapsForMFA = $Caps | where {($_.GrantControls.BuiltInControls -contains "mfa") -and ($_.state -eq "enabled")} ##Filter based on MFA and state of policy

Write-Host " `n `n "






Write-Host " Starting to check the resultant set of CA policies . . . . . . `n " 

############################################################################################################################################################
############################################################################################################################################################
##################################### Figure out if CA is in the resultant set of policies or not ##########################################################
############################################################################################################################################################
############################################################################################################################################################


## At this point, the Groups/Roles IDs that the user is part of, is stored in $Groups , or otherwise, $Groups.ID

## CA policies that we need to check in, are stored in $EnabledCapsForMFA

Foreach ($x in $EnabledCapsForMFA)                                             ################## Per Policy that is available in the $EnabledCapsForMFA ##########################

{

    Write-Host "`n Checking CA Policy `"$($x.displayName)`""
    $InFinal = $False                                                           ############# We are using this temp parameter to decide in the end if a CA policy has to be in the resultant #########################
                                                                               ############# If we find an exclusion in any way for any each CA policy, we flip this value to exclude checking #######################
    
    
    $endcheck = $False                                                          ############# This parameter to cut short the loop and come out to check other policies, by default we set this to False ##############

        $Conditions = $x.Conditions.Users                                       ############# Filtering to get Users, Groups and Roles defined in theCA policy #################


##################### 1)  Checking User Exclusion Condition. If User is already Excluded, we should not touch the CA policy ##################################

## // CheckExclusionUser 

        if ($userInforaw.id -in $Conditions.ExcludeUsers)                           ######## Checking User Exclusion ###############
            {                                                                     ######## Checking User Exclusion ###############
            $InFinal = $False                                                     #### Setting $InFinal parameter to False ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
            $endcheck = $True                                                    ### Flipping $endcheck to True to avoid other IF conditions from applying on this anymore ####
            $dp = $x.DisplayName
            $userdp = $userInforaw.displayName
            $useroid = $_.id

            Write-Host "User Exclusion - Conditional Access policy `"$dp`" contains the User `"$userdp`" `( object ID - $userObjectID `) in Exclude Condition which the User is part of"                                                                  
            }



################ 2) A  Checking Group Exclusion Condition. If User is already Excluded through group, we should not touch the CA policy ##########################


## // CheckExclusionGroup 

 $Groups | ForEach-Object {
          if ($_.id -in $Conditions.excludeGroups)
                {

                    Write-Host "Group Exclusion- Conditional Access policy `"$($x.displayName)`" contains the group `"$($_.DisplayName)`" `( object ID - $($_.id) `) in Exclude Condition which the User is part of "
                    $InFinal = $False                                                     #### Setting $InFinal parameter to False ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
                    $endcheck = $True                                                    ### Flipping $endcheck to True to avoid other IF conditions from applying on this anymore ####
                }
        }

################ 2) B  Checking Role Exclusion Condition. If User is already Excluded through Role, we should not touch the CA policy ##########################

## // CheckRoleExclusions

         $UserRoleTemplateIDs | ForEach-Object {
          if ($_.roletemplateID -in $Conditions.excludeRoles)
                {
                    Write-Host "Role Exclusion- Conditional Access policy `"$($x.DisplayName)`" contains the role `"$($_.DisplayName)`" `( Role Template ID - $($_.RoleTemplateid) `) in Exclude Condition which the User is assigned to"
                    $InFinal = $False                                                     #### Setting $InFinal parameter to False ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
                    $endcheck = $True                                                    ### Flipping $endcheck to True to avoid other IF conditions from applying on this anymore ####
                }
        }

        Write-Host "O/P Conditions.Excluderoles"
        $Conditions.excludeRoles

################ 3)  Checking In Remaining CA policies if User in Directly Included . If User is already Excluded through group or user condition , we should not touch the CA policy (EndCheck tells us that)################


##Direct User Inclusion Check

        if (($userObjectId -in $Conditions.IncludeUsers) -and ($endcheck -eq $False))     ######## Checking User Inclusion and checking if this needs to be skipped based on earlier Exclude condition ###############
            {                                                                             ######## Checking User Inclusion ###############
            $InFinal = $True                                                             #### Setting temporary parameter to True ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
  ##          Write-Host "Inclusion script running"
 ##           Write-Host " $InFinal "
            }



## User's Group Inclusion Check

if ($endcheck -ne $True)                                                                      ########### Check if Already Excluded by something using EndCheck Variable #######################

        {
         $Groups | ForEach-Object {
                  if ($_.id -in $Conditions.includeGroups)
                        {
                            $dp = $x.displayName
                            $gpName = $_.DisplayName
                            $gpID = $_.id
                          ##  Write-Host "Group Exclusion- Conditional Access policy `"$dp`" contains the group `"$gpName`" `( object ID - $gpid `) in Exclude Condition which the User is part of `n"
                            $InFinal = $True                                                     #### Setting $InFinal parameter to False ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
                            $endcheck = $False                                                    ### Flipping $endcheck to True to avoid other IF conditions from applying on this anymore ####
                            $dp = $Null
                            $gpName = $Null
                        }
                }

        }

##Direct Role Inclusion Check
if ($endcheck -ne $True){                                                                ########### Check if Already Excluded by something using EndCheck Variable #######################
        $UserRoleTemplateIDs | ForEach-Object {
          if ($_.roletemplateID -in $Conditions.includeRoles)
                {
                    $InFinal = $True                                                     #### Setting $InFinal parameter to True ####### (We use this parameter to identify in the end if a CA policy needs to be considered or not)
                    $endcheck = $False                                                    ### Flipping $endcheck to False ####
                }
        }
}



##Write-Host " $dp "
##Write-Host " $InFinal"

################ Check and Mark CA Policy for Resultant if $InFinal is set to True #######################

#CalculateResultForTrue ##Function Defined in the beginning





        if (($InFinal -eq $True) -and ($endcheck -ne $True))                                                                             ######### Checking if $InFinal has been triggered to True, and if True, add to resultant set of policies #################
            {
            
        $result = New-Object -TypeName PSObject
        $result | Add-Member -MemberType NoteProperty -Name PolicyID -Value $x.id
        $result | Add-Member -MemberType NoteProperty -Name DisplayName -Value $x.DisplayName
        $result | Add-Member -MemberType NoteProperty -Name NeedsToBeInResultant -Value "True"

        $endresult += $result

            }


}

if($endresult -eq $Null) { Write-Host " `n There are no CA policies to exclude the user to bypass MFA from " }
$endresult

#PATCH query for exclusion

#$PatchqueryCAP = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies/' + $endresult[0].policyid                                                                                         ##Build URL for the graph query for CAP patch

#$endresult[0].ExcludeUsers = $endresult[0].ExcludeUsers + $userObjectId

#$Body = $endresult[0].ExcludeUsers
#$ApiBody = ConvertTo-Json -InputObject $Body -Compress

#$UserExclusion = Invoke-RestMethod -Headers @{Authorization = "Bearer $($response.access_token)"} -Uri $PatchqueryCAP -Method PATCH -Body $Body -ContentType "application/json"

#$endresult[0].ExcludeUsers

