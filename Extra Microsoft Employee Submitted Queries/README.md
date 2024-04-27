## Microsoft Employee Submitted Queries

To make this book as real-world and practical as possible, the authors asked various Microsoft colleagues what KQL queries they use in their day-to-day work with customers. We've placed these queries throughout the book chapters and are including them in one central place here.

We also had so many queries submitted that we could not fit all of them into the chapters! The additional queries are also provided here.

### Estefani Arroyo
##### Cosmos DB Consumption. This query can help you determing the Cosmos DB request unity consumption by the physical partition, across all replicas in the replica set. If consumption is skewed among their partitions, you may want to consider remodeling your data and chose a partition key with a higher cardinality.
```KQL
CDBPartitionKeyRUConsumption 
| where TimeGenerated >= now(-1d) 
//specify collection and database 
//| where DatabaseName == "DBNAME" and CollectionName == "COLLECTIONNAME" 
// filter by operation type 
//| where operationType_s == 'Create' 
| summarize sum(todouble(RequestCharge)) by toint(PartitionKeyRangeId) 
| render columnchart 
```

##### Cosmos DB Top N(10) queries ordered by Request Unit (RU) consumption in a specific time frame.
```KQL
let topRequestsByRUcharge = CDBDataPlaneRequests  
| where TimeGenerated > ago(24h) 
| project  RequestCharge , TimeGenerated, ActivityId; 
CDBQueryRuntimeStatistics 
| project QueryText, ActivityId, DatabaseName , CollectionName 
| join kind=inner topRequestsByRUcharge on ActivityId 
| project DatabaseName , CollectionName , QueryText , RequestCharge, TimeGenerated 
| order by RequestCharge desc 
| take 10  
```

##### Cosmos DB Requests throttled (statusCode = 429) in a specific time window
```KQL
let throttledRequests = CDBDataPlaneRequests 
| where StatusCode == "429" 
| project  OperationName , TimeGenerated, ActivityId; 
CDBQueryRuntimeStatistics 
| project QueryText, ActivityId, DatabaseName , CollectionName 
| join kind=inner throttledRequests on ActivityId 
| project DatabaseName , CollectionName , QueryText , OperationName, TimeGenerated 
```

### Michael Barbush
##### Antivirus Exclusions. These three queries below are used to look for if any exclusions have been added or attempted to be added for extensions, paths or processes for the last 24 hours.

```KQL
DeviceRegistryEvents
| where RegistryKey has @"Exclusions\Extensions" and ActionType in ("RegistryValueDeleted","RegistryKeyDeleted","RegistryKeyCreated","RegistryValueSet","RegistryKeyRenamed") and Timestamp > ago(24h)
| sort by Timestamp
```

```KQL
DeviceRegistryEvents
| where RegistryKey has @"Exclusions\Paths" and ActionType in ("RegistryValueDeleted","RegistryKeyDeleted","RegistryKeyCreated","RegistryValueSet","RegistryKeyRenamed") and Timestamp > ago(24h)
| sort by Timestamp
```

```KQL
DeviceRegistryEvents
| where RegistryKey has @"Exclusions\Processes" and ActionType in ("RegistryValueDeleted","RegistryKeyDeleted","RegistryKeyCreated","RegistryValueSet","RegistryKeyRenamed") and Timestamp > ago(24h)
| sort by Timestamp
```

##### Applications using auto proxy. This query is useful for operational and security teams alike. If you don’t know which applications are currently leveraging WPAD this will help you start to build that list. If you do know and see suspicious names or unexpected applications, these should be further investigated. 
```KQL
//Change timeframe to fit needs
DeviceNetworkEvents
| where RemoteUrl has 'wpad' and Timestamp > ago(1h)
| summarize by InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, RemoteUrl, ActionType
| sort by InitiatingProcessFileName asc
```

##### Joining data between tables provides interesting detection capabilities, for instance you can combine filename data and certificate information to detect where a filename may have been changed to evade detection – Michael Barbush
```KQL
DeviceFileEvents 
| where InitiatingProcessFileName has_any ("any.exe") and isnotempty(InitiatingProcessSHA1) and Timestamp > ago(24h) 
| summarize by strangefiles=InitiatingProcessSHA1 
| join kind=inner(DeviceFileCertificateInfo 
| where isnotempty(IsTrusted)) on $left.strangefiles == $right.SHA1 
| summarize by strangefiles, Signer, Issuer, IsSigned, IsTrusted 
```

### Kristopher Bash
##### Exploring client info for a particular application. This query summarizes the count of API requests to Microsoft Graph APIs for a specific application, with metadata about the clients, such as IP Address and UserAgent strings. This can be useful to understand more about deployment and use of a specific application in your tenant. The Location field reflects the region of the Microsoft Graph service that serves the request. This is typically the closest region to the client. 
```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(3d)
| where AppId =='e9134e10-fea8-4167-a8d0-94c0e715bcea'
| summarize RequestCount=count() by  Location, IPAddress, UserAgent
```

##### Exploring traffic patterns by time of day. This query will use the timestamp(TimeGenerated) to understand the traffic patterns in your tenant to Microsoft Graph APIs.
```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated  between (ago(3d) .. ago(1h)) 
| summarize EventCount = count() by bin(TimeGenerated, 10m)
| render timechart
    with (
    title="Recent traffic patterns",
    xtitle="Time",
    ytitle="Requests",
    legend=hidden
    )
```
##### Microsoft Graph Activity Logs include an identifier field (SignInActivityId) which can be used to join the logs with SignInLogs. SignInLogs provide detail of the authentication request. By joining these tables, you can explore token issuance and usage of the token. As SignInLogs are split into multiple log categories/tables, a more comprehensive join benefits from union of the SignInLogs tables before joining.
```KQL
MicrosoftGraphActivityLogs 
| where TimeGenerated > ago(3d) 
| where SignInActivityId == 'tPcQvrtP4kirTjs98vmiAA' 
| join kind=leftouter (union SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs 
    | where TimeGenerated > ago(4d) 
    | summarize arg_max(TimeGenerated, *) by UniqueTokenIdentifier 
    ) 
    on $left.SignInActivityId == $right.UniqueTokenIdentifier 
| limit 100
```

```KQL
MicrosoftGraphActivityLogs 
| where TimeGenerated > ago(3d) 
| where ResponseStatusCode == 429 
| extend path = replace_string(replace_string(replace_regex(tostring(parse_url(RequestUri).Path), @'(\/)+','//'),'v1.0/',''),'beta/','') 
| extend UriSegments =  extract_all(@'\/([A-z2]+|\$batch)($|\/|\(|\$)',dynamic([1]),tolower(path)) 
| extend OperationResource = strcat_array(UriSegments,'/')| summarize RateLimitedCount=count() by AppId, OperationResource, RequestMethod 
| sort by RateLimitedCount desc 
| limit 100
```

##### We may want to understand what applications in the tenant are using a specific API request. This query filters by aspects of the requestUri to summarize applications using a specific API. The RequestUri can be extracted, parsed, as illustrated in this example, or matched for substrings with the has operator.
```KQL
MicrosoftGraphActivityLogs 
| where TimeGenerated > ago(3d) 
| extend path = replace_string(replace_string(replace_regex(tostring(parse_url(RequestUri).Path), @'(\/)+','//'),'v1.0/',''),'beta/','') 
| extend UriSegments =  extract_all(@'\/([A-z2]+|\$batch)($|\/|\(|\$)',dynamic([1]),tolower(path)) 
| extend OperationResource = strcat_array(UriSegments,'/') 
| where OperationResource == 'oauth2permissiongrants' 
| summarize RequestCount=count() by AppId 
```

##### API requests that fail due to authorization (insufficient permissions) show up in the logs with a ResponseStatusCode of 403. There are other fields in the logs that can be useful to investigate authorization concerns.
```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(3d)
| where ResponseStatusCode == 4030
| where RequestUri has '/auditLogs'
| summarize RequestCount=count() by AppId, Scopes, Roles, Wids, ClientAuthMethod
| sort by RequestCount desc
```

##### We may want to understand what applications in the tenant are using a specific API request. This query filters by aspects of the requestUri to summarize applications using a specific API. The RequestUri can be parsed, as illustrated in this example, or matched for substrings with the has operator. 
```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(3d)
| extend path = replace_string(replace_string(replace_regex(tostring(parse_url(RequestUri).Path), @'(\/)+','//'),'v1.0/',''),'beta/','')
| extend UriSegments =  extract_all(@'\/([A-z2]+|\$batch)($|\/|\(|\$)',dynamic([1]),tolower(path))
| extend OperationResource = strcat_array(UriSegments,'/')
| where OperationResource == 'oauth2permissiongrants'
| summarize RequestCount=count() by AppId
```

```KQL
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(3d)
| where RequestUri has 'oauth2permissiongrants'
| summarize RequestCount=count() by AppId
```

### Bailey Bercik
##### Drilling into Microsoft Entra ID Governance. These queries below are helpful as an administrator to determine usage patterns in access reviews.  This can be helpful for seeing how frequently these requests are being created and whether the admin can proactively assign these resources in a better way. Perhaps patterns on which types of users requesting access will emerge or seeing whether a particular user is inundated with review requests. The second is helpful if an administrator  wants to see whether access requests were approved or denied by reviewers. Justification and target resources will also be shown to give the administrator  more information. Finally, if an administrator wants to see which access requests expired. Perhaps to know whether requests should be rerouted to another user for approval instead.

```KQL
AuditLogs
| where LoggedByService == "Access Reviews"
| where OperationName == "Create request"
| order by TimeGenerated asc
```
```KQL
AuditLogs
| where LoggedByService == "Access Reviews"
| where OperationName == "Request approved" or OperationName == "Request denied"
| order by TimeGenerated asc
```

```KQL
AuditLogs
| where LoggedByService == "Access Reviews"
| where OperationName == "Request expired"
| order by TimeGenerated asc
```

### Keith Brewer
##### Tracking and visualizing Microsoft Entra ID authentication methods. This query enables you to visualize authentication method use over time during a registration campaign. This can also be placed in a workbook for a dashboard view. 
```KQL
SigninLogs
| where ResultType == 0 or ResultType == 50074
// Filter out the AADC Sync Account
| where SignInIdentifier !startswith "Sync_"
// Filter out Sign-in Events from ADFS Connect Health
| where SourceSystem == "Azure AD"
| extend AuthenticationDetails = todynamic(AuthenticationDetails)
| mv-expand AuthenticationDetails
| extend authenticationMethod_ = tostring(parse_json(AuthenticationDetails).authenticationMethod)
// Filter out sign-in events without relevant Authentication Method Detail
| where authenticationMethod_ != "Previously satisfied" and authenticationMethod_ != ""
| make-series SignIns = count() default = 0 on TimeGenerated step 1d by authenticationMethod_
```

### Chad Cox
##### Here are two queries that really demonstrate the power of mv-expand and parse. The first query allows you to determine which administrative activity was performed if that administrator role had any risk associated with it. The second query displays any changes to the most used applications which if suspicious might be an indication of an attack or malicious activity.
```KQL
let privroles = pack_array("Application Administrator","Authentication Administrator","Cloud Application Administrator","Conditional Access Administrator","Exchange Administrator","Global Administrator","Helpdesk Administrator","Hybrid Identity Administrator","Password Administrator","Privileged Authentication Administrator","Privileged Role Administrator","Security Administrator","SharePoint Administrator","User Administrator");
let privusers = AuditLogs 
| where TimeGenerated > ago(60d) and ActivityDisplayName == 'Add member to role completed (PIM activation)' and Category == "RoleManagement" 
| extend Caller = tostring(InitiatedBy.user.userPrincipalName) 
| extend Role = tostring(TargetResources[0].displayName) 
| where Role in (privroles) 
| distinct Caller;
let Activity =  AuditLogs
    | mv-expand ParsedFields = parse_json(TargetResources)
    | extend Target = tostring(ParsedFields.userPrincipalName), DisplayName = tostring(ParsedFields.displayName)
    | project TimeGenerated, Target, DisplayName, ParsedFields, OperationName;
    let RiskyUsers = SigninLogs
    | where RiskLevelDuringSignIn == "high"
    | where RiskState == "atRisk"
    | project TimeGenerated,UserPrincipalName, UserDisplayName, RiskDetail, RiskLevelDuringSignIn, RiskState;
    Activity
    | join kind=inner(RiskyUsers) on $left.DisplayName==$right.UserDisplayName
    | where TimeGenerated >= ago(7d) and UserPrincipalName in~ (privusers)
    | distinct UserDisplayName, RiskDetail, RiskLevelDuringSignIn, OperationName
```

```KQL
let MostUsedApps = SigninLogs
    | where TimeGenerated > ago(30d)
    | summarize dcount(CorrelationId) by AppId, AppDisplayName
    | top 100 by dcount_CorrelationId;
    //| summarize TopApps = make_list(AppId);
let Activty = AuditLogs
//| where OperationName has "application"
| mv-expand ParsedFields = parse_json(TargetResources)
| extend TargetId = tostring(ParsedFields.id)
| extend TargetName = tostring(ParsedFields.displayName)
| project TargetId, TargetName, OperationName, ActivityDisplayName;
MostUsedApps
| join kind = inner(Activty) on $left.AppId==$right.TargetId
| where isnotempty(TargetId)
| project AppId, AppDisplayName, ActivityDisplayName, OperationName
```

### Jack Davis
##### Helpful in evaluating where Single-Factor Authentication has been used to successfully sign into Intune-managed Entra ID Joined (AADJ) Windows endpoints by users not identified as the Primary User of those endpoints. 
```KQL
let dc = IntuneDevices 
| extend entra_DeviceID = tostring(ReferenceId); 
let entraIDsignin = SigninLogs 
| extend entra_DeviceID = tostring(DeviceDetail.deviceId); 
entraIDsignin 
| join kind=inner dc on entra_DeviceID 
| extend authenticationMethod_ = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod) 
| extend succeeded_ = tostring(parse_json(AuthenticationDetails)[0].succeeded) 
| extend IntuneDeviceID = DeviceId 
| extend trustType_ = tostring(DeviceDetail.trustType) 
| where trustType_ == 'Azure AD joined' 
| where ManagedBy == 'Intune' 
| where Resource == "Microsoft.aadiam" and AppDisplayName == "Windows Sign In" 
| where succeeded_ == 'true' 
| where authenticationMethod_== "Password" and succeeded_ == "true" 
| where AuthenticationRequirement == 'singleFactorAuthentication' 
| where PrimaryUser != UserId 
| summarize logins=count() by UserPrincipalName, IntuneDeviceID 
| render columnchart
```

### Varun Dhawan
##### This query helps you find short lived connections in your database. Sample Output: A time-chart showing the trends long vs short lived connection over time. If your application is designed around short-lived connections and you expect many queries from different client sessions, then it may benefit from using connection pooling.
```KQL
AzureDiagnostics 
| where Resource =~ "varund-qpi-demo" 
| where ResourceProvider =="MICROSOFT.DBFORPOSTGRESQL" 
| where Category == "PostgreSQLLogs" 
| where TimeGenerated >= ago(2d) 
| where Message contains "disconnection: session time" 
| extend pgmessage = tostring(split(Message, "disconnection: session time: ")[-1]) 
| extend myuser = tostring(split(tostring(split(pgmessage, " database=")[-2]), " user=")[-1]) 
| extend hours = todecimal(substring(pgmessage, 0, 1)) 
| extend minutes = todecimal(substring(pgmessage, 2, 2)) 
| extend seconds = todecimal(substring(pgmessage, 5, 2)) 
| extend milliseconds = todecimal(substring(pgmessage, 7, 4)) 
| extend connection_life_seconds = hours*60*60+minutes*60+seconds+milliseconds 
| where myuser != 'azuresu' 
| extend connection_type = case(connection_life_seconds < 60 , strcat("Short Live Connection"), connection_life_seconds between (60 .. 1200) , strcat("Normal Live Connection"),connection_life_seconds >1200, strcat("Long Live Connections"), "")
| summarize max(connection_life_seconds) by TimeGenerated,connection_type,myuser 
| render timechart
```

##### This query filters the PostgreSQL logs to identify failed login attempts by checking for specific log messages. It projects the time, resource, and log message details.
```kql 
// Query to monitor failed login attempts 
AzureDiagnostics 
| where Resource =~ "varund-qpi-demo" 
| where Category == "PostgreSQLLogs" 
| where Message contains "FATAL:  password authentication failed for user" 
| project TimeGenerated, Resource, Message 
| sort by TimeGenerated desc 
```

##### This query looks for log entries indicating long-running queries in PostgreSQL (longer than 1 second) by extracting the duration from log messages.
```kql 
//Query to check for long-running queries 
AzureDiagnostics 
| where Resource =~ "varund-qpi-demo" 
| where Category == "PostgreSQLLogs" 
| extend query_duration = extract("duration: ([^ ]+)", 1, Message) 
| where isnotempty(query_duration) and todouble(query_duration) > 1000 
| project TimeGenerated, Resource, Message, query_duration 
| sort by query_duration desc 
```

##### This query counts the number of successful database connections over time, summarized hourly.
```kql 
AzureDiagnostics 
| where Resource =~ "varund-qpi-demo" 
| where Category == "PostgreSQLLogs" 
| where Message contains "connection authorized" 
| summarize ConnectionCount=count() by bin(TimeGenerated, 1h) 
| render timechart 
```

##### This query filters for error logs in PostgreSQL logs, providing insights into recent errors that have occurred.
```kql 
AzureDiagnostics 
| where Resource =~ "varund-qpi-demo" 
| where Category == "PostgreSQLLogs" 
| where errorLevel_s == "LOG" 
| project TimeGenerated, Resource, Message 
| sort by TimeGenerated desc 
```

##### This query filters Azure metrics logs for a specific PostgreSQL Flexible Server instance. It retrieves and charts the CPU utilization percentage over time.
```kql 
// Query to monitor CPU utilization of Azure Database for PostgreSQL Flexible Server 
AzureMetrics 
| where Resource =~ "varund-qpi-demo" 
| where ResourceProvider == "MICROSOFT.DBFORPOSTGRESQL" 
| where MetricName == "cpu_percent" 
| project TimeGenerated, Average 
| render timechart 
```

##### This query measures the number of active connections to the PostgreSQL server.
```kql 
// Query to analyze the number of database connections 
AzureMetrics 
| where Resource =~ "varund-qpi-demo" 
| where ResourceProvider == "MICROSOFT.DBFORPOSTGRESQL" 
| where MetricName in ("active_connections") 
| project TimeGenerated, MetricName, Average 
| render timechart  
```

##### This query tracks the storage utilization percentage of the PostgreSQL server over time.
```kql 
// Query to check storage utilization 
AzureMetrics 
| where Resource =~ "varund-qpi-demo" 
| where ResourceProvider == "MICROSOFT.DBFORPOSTGRESQL" 
| where MetricName == "storage_percent" 
| project TimeGenerated, Average 
| render timechart 
```

##### This query monitors the inbound and outbound network traffic for the PostgreSQL server.
```kql 
// Query to identify inbound and outbound network traffic 
AzureMetrics 
| where Resource =~ "varund-qpi-demo" 
| where ResourceProvider == "MICROSOFT.DBFORPOSTGRESQL" 
| where MetricName in ("network_bytes_ingress", "network_bytes_egress") 
| project TimeGenerated, MetricName, Average 
| render timechart 
```

### Michael Epping
##### Looking for iOS and macOS SSO Extension usage. The query below will get a summary of sign-ins facilitated by the iOS and/or macOS SSO Extension deployed via MDM provider. This helps the administrator determine if the SSO Extension is working as expected for those users. This is recommended to be deployed for all Apple devices. 
```KQL
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| extend operatingSystem = parse_json(DeviceDetail).operatingSystem
| where operatingSystem == "MacOs" or operatingSystem == "Ios"
| where UserAgent startswith "Mac%20SSO%20Extension" or UserAgent startswith "AuthenticatorSSOExtension"
| summarize count() by UserPrincipalName, tostring(operatingSystem)
| sort by count_
```

### Marius Folling
##### Using regex for searching for MFA phone number changes can be a valuable hunting strategy for understanding user compromise. Regex can be used to look for particular patterns for phone numbers, for instance if your business is in Europe, then USA formatted numbers may be suspicious 
```KQL
CloudAppEvents 
| where Timestamp >= datetime("Insert date") 
| where ActionType == "Update user." and RawEventData contains "StrongAuthentication" 
| extend target = RawEventData.ObjectId 
| mvexpand ModifiedProperties = parse_json(RawEventData.ModifiedProperties) 
| where ModifiedProperties matches regex @"\+\d{1,3}\s*\d{9,}" 
| mvexpand ModifiedProperties = parse_json(ModifiedProperties) 
| where ModifiedProperties contains "NewValue" and ModifiedProperties matches regex @"\+\d{1,3}\s*\d{9,}" 
| extend PhoneNumber = extract(@"\+\d{1,3}\s*\d{9,}", 0, tostring(ModifiedProperties)) 
| project Timestamp, target, PhoneNumber
``` 

### Cosmin Guilman
##### Entra ID dynamic group processing changes. This query will help you track a dynamic group membership change processing taking place in your tenant for whatever group you specify. This can be helpful when making large changes to the dynamic group membership as well as normal day to day churn of the group.
```KQL
AuditLogs
| where Category == "GroupManagement"
| where TargetResources == "REPLACE" // group id you want to monitor
| where ActivityDisplayName in ("Add member to group","Remove member from group") or ActivityDisplayName =="Update group"
| summarize count() by TimeGenerated
| render timechart
```

##### Legacy authentication is important to also track, as it is not MFA aware. This query will return a breakdown of modern vs legacy TLS sessions, summarized by applicationId and application display name. The same logic can be easily translated to interactive sign-in sessions by replacing the function used to SigninLogs. You can easily breakdown sessions over time by specifying the lookback period in the query, then summarize your results by minutes / hours / days.
```KQL
AADNonInteractiveUserSignInLogs 
| extend DeviceRaw=parse_json(DeviceDetail) 
| extend DeviceOS=DeviceRaw.operatingSystem, DeviceId=DeviceRaw.deviceId,DeviceBrowser=DeviceRaw.browser 
| where AuthenticationProcessingDetails has "Legacy TLS" 
| extend JsonAuthProcDetails = parse_json(AuthenticationProcessingDetails) 
| mv-apply JsonAuthProcDetails on (  
where JsonAuthProcDetails.key startswith "Legacy TLS"  
| project HasLegacyTls=JsonAuthProcDetails.value)  
| summarize Total=count(),LegacyTLS=countif(HasLegacyTls == true), ModernTLS=countif(HasLegacyTls != true) by AppDisplayName, AppId, tostring(DeviceOS), tostring(DeviceRaw), UserDisplayName, UserId, UserPrincipalName 
```

##### Identify sign-in sessions where a user is blocked by Conditional Access that requires specific regions. IPv6 rollout to Azure services is in progress and the country location mapping is sometimes incorrect / missing.
```KQL
SigninLogs
| where TimeGenerated >=ago(90d)
| mv-expand ConditionalAccessPolicies
| extend CAID = tostring(ConditionalAccessPolicies.id)
| extend CAResult = tostring(ConditionalAccessPolicies.result)
| extend CAPolicyName = tostring(ConditionalAccessPolicies.displayName)
| extend Device = tostring(DeviceDetail.operatingSystem)
| extend LocationReg = tostring(LocationDetails.countryOrRegion)
| where CAResult == "failure"
| where CAID == "REPLACE" // CA policy ID specific to tenant
| where ResultType =="53003" //Blocked by CA
| where IPAddress contains ":" // Ipv6
| where Device == "Android" or Device contains "ios"
| summarize dcount(CorrelationId) by TimeGenerated, UserPrincipalName, AppDisplayName, CAPolicyName, CorrelationId, IPAddress, Device, LocationReg
```

### Tim Haintz
##### Understanding email authentication patterns can be valuable to understand suspicious email flows into your environment. Phishing attacks are less likely to have properly configured email security, and are more likely to fail authentication requirements such as SPF or DMARC.
```KQL
EmailEvents 
| where Timestamp > ago(20d) 
| extend AuthenticationDetails = todynamic(AuthenticationDetails) 
| project SenderFromAddress, 
            SenderDisplayName, 
            RecipientEmailAddress, 
            AuthDetailsSPF=parse_json(AuthenticationDetails.SPF), 
            AuthDetailsDKIM=parse_json(AuthenticationDetails.DKIM), 
            AuthDetailsDMARC=parse_json(AuthenticationDetails.DMARC), 
            AuthDetailsCompAuth=parse_json(AuthenticationDetails.CompAuth) 
| summarize by SenderFromAddress, SenderDisplayName, RecipientEmailAddress, tostring(AuthDetailsSPF), tostring(AuthDetailsDKIM), tostring(AuthDetailsDMARC), tostring(AuthDetailsCompAuth) 
```

### Franck Heilmann
##### For a token protection enablement in conditional access, to minimize the likelihood of user disruption due to applications or device incompatibility, we highly recommend doing staged deployment and actively monitoring the sign-in logs. This query gives administrators a per token protection conditional access rules user impact view.
```KQL
let alertThreshold = 10.0; //Alert will be triggered when this threashold (%) will be crossed. Default is 10%
let duration = timespan(30d); //Duration (Azure Monitor only support alerts with duration looking pass data from 14 days) 
let totalRequestsWithRisk = (duration: timespan) {
    SigninLogs   
    | where TimeGenerated >= ago(duration)   
    | summarize total = count()
}; 
let eval = (columnName: string) {
    SigninLogs
    | where TimeGenerated >= ago(duration) 
    | summarize requestsSend = count() by column_ifexists(columnName, “”) 
    | project column_ifexists(columnName, “”), requestsSend    
    | extend total= toscalar(totalRequestsWithRisk(duration))    
    | extend percentage = round((toreal(requestsSend) / toreal(total)) * 100, 2)
    | where percentage > alertThreshold
    | project
        column_ifexists(columnName, “”),
        requests_send=requestsSend,
        total_requests=total,
        percentage_total = strcat(percentage, “%”),
        query_eval_window_days_hours_mins= format_timespan(duration, “d: h: m”) //days  
    | order by requests_send desc
};
eval(“UserPrincipalName”) //Can pass other column e.g. UserPrincipalName, etc
```

##### For enabling token protection in conditional acess, to minimize the likelihood of user disruption due to applications or device incompatibility, we highly recommend doing staged deployment and actively monitoring the sign-in logs. This query gives an admin a per application view of token protection conditional access rules impact.
```KQL
//Per Apps query  
// Select the log you want to query (SigninLogs or AADNonInteractiveUserSignInLogs )  
//SigninLogs  
AADNonInteractiveUserSignInLogs  
// Adjust the time range below  
| where TimeGenerated > ago(7d)  
| project Id,ConditionalAccessPolicies, Status,UserPrincipalName, AppDisplayName, ResourceDisplayName  
| where ConditionalAccessPolicies != "[]"  
| where ResourceDisplayName == "Office 365 Exchange Online" or ResourceDisplayName =="Office 365 SharePoint Online"  
//Add userPrinicpalName if you want to filter   
// | where UserPrincipalName =="<user_principal_Name>"  
| mv-expand todynamic(ConditionalAccessPolicies)  
| where ConditionalAccessPolicies ["enforcedSessionControls"] contains '["Binding"]' or ConditionalAccessPolicies ["enforcedSessionControls"] contains '["SignInTokenProtection"]'  
| where ConditionalAccessPolicies.result !="reportOnlyNotApplied" and ConditionalAccessPolicies.result !="notApplied"  
| extend SessionNotSatisfyResult = ConditionalAccessPolicies["sessionControlsNotSatisfied"]  
| extend Result = case (SessionNotSatisfyResult contains 'SignInTokenProtection' or SessionNotSatisfyResult contains 'SignInTokenProtection', 'Block','Allow') 
| summarize by Id,UserPrincipalName, AppDisplayName, Result  
| summarize Requests = count(), Users = dcount(UserPrincipalName), Block = countif(Result == "Block"), Allow = countif(Result == "Allow"), BlockedUsers = dcountif(UserPrincipalName, Result == "Block") by AppDisplayName  
| extend PctAllowed = round(100.0 * Allow/(Allow+Block), 2)  
| sort by Requests desc
```

##### Token protection in conditional access deployment, to minimize the likelihood of user disruption due to applications or device incompatibility, we highly recommend doing staged deployment and actively monitoring the sign-in logs. This query gives an administrator a per users view of token protection conditional access rules impact. 
```KQL
//Per users query  
// Select the log you want to query (SigninLogs or AADNonInteractiveUserSignInLogs )  
//SigninLogs  
AADNonInteractiveUserSignInLogs  
// Adjust the time range below  
| where TimeGenerated > ago(7d)  
| project Id,ConditionalAccessPolicies, UserPrincipalName, AppDisplayName, ResourceDisplayName  
| where ConditionalAccessPolicies != "[]" 
| where ResourceDisplayName == "Office 365 Exchange Online" or ResourceDisplayName =="Office 365 SharePoint Online"  
//Add userPrincipalName if you want to filter   
// | where UserPrincipalName =="<user_principal_Name>"  
| mv-expand todynamic(ConditionalAccessPolicies) 
| where ConditionalAccessPolicies ["enforcedSessionControls"] contains '["Binding"]' or ConditionalAccessPolicies ["enforcedSessionControls"] contains '["SignInTokenProtection"]' 
| where ConditionalAccessPolicies.result !="reportOnlyNotApplied" and ConditionalAccessPolicies.result !="notApplied"  
| extend SessionNotSatisfyResult = ConditionalAccessPolicies.sessionControlsNotSatisfied  
| extend Result = case (SessionNotSatisfyResult contains 'SignInTokenProtection' or SessionNotSatisfyResult contains 'SignInTokenProtection', 'Block','Allow') 
| summarize by Id, UserPrincipalName, AppDisplayName, ResourceDisplayName,Result   
| summarize Requests = count(),Block = countif(Result == "Block"), Allow = countif(Result == "Allow") by UserPrincipalName, AppDisplayName,ResourceDisplayName  
| extend PctAllowed = round(100.0 * Allow/(Allow+Block), 2)  
| sort by UserPrincipalName asc
```

### Mark Hopper
##### Intune Insights. These queries can help you get a sense of what is happening with your devices in Intune. The first query will show you the count of successful crate, delete and patch events for the last seven days. The second will provide a view of how many device enroll ment success and failures broken out by operating system type. Looking for patterns and changes can help indicate something is not working as expected.
```KQL
IntuneAuditLogs
| where TimeGenerated > ago(7d)
| where ResultType == "Success"
| where OperationName has_any ("Create", "Delete", "Patch")
| summarize Operations=count() by OperationName, Identity
| sort by Operations, Identity
```

```KQL
IntuneOperationalLogs 
| where OperationName == "Enrollment" 
| extend PropertiesJson = todynamic(Properties)
| extend OS = tostring(PropertiesJson["Os"]) 
| extend EnrollmentTimeUTC = todatetime(PropertiesJson["EnrollmentTimeUTC"])
| extend EnrollmentType = tostring(PropertiesJson["EnrollmentType"])
| project OS, Date = format_datetime(EnrollmentTimeUTC, 'M-d-yyyy'), Result
| summarize 
    iOS_Successful_Enrollments = countif(Result == "Success" and OS == "iOS"), 
    iOS_Failed_Enrollments = countif(Result == "Fail" and OS == "iOS"), 
    Android_Successful_Enrollmenst = countif(Result == "Success" and OS == "Android"),
    Android_Failed_Enrollments = countif(Result == "Fail" and OS == "Android"),
    Windows_Succesful_Enrollments = countif(Result == "Success" and OS == "Windows"),
    Windows_Failed_Enrollments = countif(Result == "Fail" and OS == "Windows")
    by Date
```

##### This query is helpful in analyzing audit activity specifically which objects (policies, apps, profiles, etc) have been deleted and by which identity within the last 7 days.
```KQL
IntuneAuditLogs
| where TimeGenerated > ago(7d)
| where ResultType == "Success"
| where OperationName has ("Delete")
| extend PropertiesJson = todynamic(Properties)
| extend ObjectNames = tostring(PropertiesJson["TargetDisplayNames"])  
| extend ObjectIds = tostring(PropertiesJson["TargetObjectIds"])
```

### Laura Hutchcroft
##### Looking for failed KeyVault operations. The query below helps monitor for failed operations in the last 24 hours. Frequent failures can indicate an adversary trying to gain unauthorized access. These should be investigated.

```KQL
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResultType != "Success"
```

##### Looking for failed sign-in events. The query below helps monitor for failed sign-in events in the last 24 hours. Frequent failures can indicate an adversary trying to gain unauthorized access. These should be investigated and understood. 

```KQL
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType !in ("0", "50125", "50140")
```
##### Monitoring KeyVault secret operations. The query below helps monitor for all secret operations over the last 24 hours. Frequent secret operations could indicate an adversary trying to steal sensitive information. These should be investigated and understood.

```KQL
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where Category == "AuditEvent"
| where OperationName contains "secret"
```

##### Monitoring KeyVault secret operations. The query below helps monitor for all secret operations over the last 24 hours by a user. If a user is performing more operations then usual this could be a sign of compromise. These should be investigated and understood.
```KQL
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where Caller_s == "<user>"
| where TimeGenerated > ago(24h)
```

##### Monitoring KeyVault secret operations. The query below helps monitor keyvault throttled requests. A sudden increase in throttled requests could indicate a denial of service attack. These should be investigated and understood.
```KQL
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ThrottlePolicy =~ "KeyVaultThrottlingPolicy"
| where TimeGenerated > ago(24h)
```

##### Monitoring IaaS Virtual Machines. This query looks at common performance metrics for virtual machines to help you look at resource consumption and if the virtual machines are sized correctly.
```KQL
Perf
| where TimeGenerated > ago(1h)
| where (ObjectName == "Processor" and CounterName == "% Processor Time") or 
        (ObjectName == "Memory" and CounterName == "Available MBytes")
| summarize avg(CounterValue) by Computer, CounterName
```

##### Monitoring network traffic flows. This query looks at network flows per hour for the last 24 hours. Look for patterns and suspicious or long running network flows. Please see https://aka.ms/KQLMSPress/NetFlows for setup requirements.
```KQL
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| summarize sum(InboundFlows_d), sum(OutboundFlows_d) by bin(TimeGenerated, 1h)
```

### Jef Kazimer
##### Delving into the identity governance operations. These queries offers critical insights into activities necessitating further scrutiny. This suite of queries is designed to enumerate operations linked to pivotal identity governance features, thereby illuminating the extent of Identity Governance and Administration (IGA) activities. It aims to enhance administrator awareness regarding configuration modifications, as well as end-user actions including access requests, approvals, and subsequent assignments. Further exploration of specific operations provides a deeper understanding of the access governance state, showcasing the efficiency of implemented access control measures.  Note: Ensure your query time range includes as much history that you have enabled for retention in your log analytics workspace. 
```KQL
AuditLogs
| where LoggedByService == "Entitlement Management"
| summarize OperationCount = count() by OperationName, AADOperationType
| order by OperationCount desc
```

```KQL
AuditLogs
| where LoggedByService == "Access Reviews"
| summarize OperationCount = count() by OperationName, AADOperationType
| order by OperationCount desc
```

```KQL
AuditLogs
| where LoggedByService == "Lifecycle Workflows"
| summarize OperationCount = count() by OperationName, AADOperationType
| order by OperationCount desc
```

```KQL
AuditLogs
| where LoggedByService == "PIM"
| summarize OperationCount = count() by OperationName, AADOperationType
| order by OperationCount desc
```

### Corissa Koopmans
##### Here are two queries that really demonstrate the power of mv-expand and parse. The first query allows you to determine which administrative activity was performed if that administrator role had any risk associated with it. The second query displays any changes to the most used applications which if suspicious might be an indication of an attack or malicious activity.
```KQL
let privroles = pack_array("Application Administrator","Authentication Administrator","Cloud Application Administrator","Conditional Access Administrator","Exchange Administrator","Global Administrator","Helpdesk Administrator","Hybrid Identity Administrator","Password Administrator","Privileged Authentication Administrator","Privileged Role Administrator","Security Administrator","SharePoint Administrator","User Administrator");
let privusers = AuditLogs 
| where TimeGenerated > ago(60d) and ActivityDisplayName == 'Add member to role completed (PIM activation)' and Category == "RoleManagement" 
| extend Caller = tostring(InitiatedBy.user.userPrincipalName) 
| extend Role = tostring(TargetResources[0].displayName) 
| where Role in (privroles) 
| distinct Caller;
let Activity =  AuditLogs
    | mv-expand ParsedFields = parse_json(TargetResources)
    | extend Target = tostring(ParsedFields.userPrincipalName), DisplayName = tostring(ParsedFields.displayName)
    | project TimeGenerated, Target, DisplayName, ParsedFields, OperationName;
    let RiskyUsers = SigninLogs
    | where RiskLevelDuringSignIn == "high"
    | where RiskState == "atRisk"
    | project TimeGenerated,UserPrincipalName, UserDisplayName, RiskDetail, RiskLevelDuringSignIn, RiskState;
    Activity
    | join kind=inner(RiskyUsers) on $left.DisplayName==$right.UserDisplayName
    | where TimeGenerated >= ago(7d) and UserPrincipalName in~ (privusers)
    | distinct UserDisplayName, RiskDetail, RiskLevelDuringSignIn, OperationName
```

```KQL
let MostUsedApps = SigninLogs
    | where TimeGenerated > ago(30d)
    | summarize dcount(CorrelationId) by AppId, AppDisplayName
    | top 100 by dcount_CorrelationId;
    //| summarize TopApps = make_list(AppId);
let Activty = AuditLogs
//| where OperationName has "application"
| mv-expand ParsedFields = parse_json(TargetResources)
| extend TargetId = tostring(ParsedFields.id)
| extend TargetName = tostring(ParsedFields.displayName)
| project TargetId, TargetName, OperationName, ActivityDisplayName;
MostUsedApps
| join kind = inner(Activty) on $left.AppId==$right.TargetId
| where isnotempty(TargetId)
| project AppId, AppDisplayName, ActivityDisplayName, OperationName
```

##### Using mv-expand can provide interesting detection capabilities. Users coming from multiple devices within a relatively short period of time can be an indicator of a malicious actor.
```KQL
SigninLogs 
| where TimeGenerated > ago(90d) 
| mv-expand ParsedFields = parse_json(AuthenticationDetails) 
| extend AuthMethod = ParsedFields.authenticationMethod 
| extend ParsedFields2 = parse_json(DeviceDetail) 
| extend DeviceID = tostring(ParsedFields2.deviceId) 
| extend ParsedFields3 = parse_json(Status) 
| extend SigninStatus = tostring(ParsedFields3.errorCode) 
| where AuthMethod != "Previously satisfied" 
| where isnotempty(DeviceID) 
| where SigninStatus == 0 
| summarize dcount(DeviceID) by UserDisplayName 
| order by dcount_DeviceID desc 
```

##### Using mv-expand can provide interesting detection capabilities. Users coming from multiple devices within a relatively short period of time can be an indicator of a malicious actor.
```KQL
SigninLogs 
| where TimeGenerated > ago(90d) 
| mv-expand ParsedFields = parse_json(AuthenticationDetails) 
| extend AuthMethod = ParsedFields.authenticationMethod 
| extend ParsedFields2 = parse_json(DeviceDetail) 
| extend DeviceID = tostring(ParsedFields2.deviceId) 
| extend ParsedFields3 = parse_json(Status) 
| extend SigninStatus = tostring(ParsedFields3.errorCode) 
| where AuthMethod != "Previously satisfied" 
| where isnotempty(DeviceID) 
| where SigninStatus == 0 
| summarize dcount(DeviceID) by UserDisplayName 
| order by dcount_DeviceID desc 
```

##### You can additionally query only for a specific user of interest by casting that user as a variable at the top of your query.
```KQL
let user = "user ID here"; 
SigninLogs 
|where TimeGenerated > ago(90d) 
|where UserId == user 
| mv-expand ParsedFields = parse_json(AuthenticationDetails) 
| extend AuthMethod = ParsedFields.authenticationMethod 
| extend ParsedFields2 = parse_json(DeviceDetail) 
| extend DeviceID = tostring(ParsedFields2.deviceId) 
| extend DeviceName = tostring(ParsedFields2.displayName) 
| extend DeviceOS = tostring(ParsedFields2.operatingSystem) 
| extend DeviceBrowser = tostring(ParsedFields2.browser) 
| extend ParsedFields3 = parse_json(Status) 
| extend SigninStatus = tostring(ParsedFields3.errorCode) 
| where AuthMethod != "Previously satisfied" 
| where isnotempty(DeviceID) 
| where SigninStatus == 0 
| summarize count() by UserDisplayName, UserId, DeviceID, DeviceName, DeviceOS, DeviceBrowser, SigninStatus 
```

### Gloria Lee
##### Sudden changes from normal behavior can indicate an issue that needs to be investigated. The first query looks for detect increasing failure rates. As necessary, you can adjust the ratio at the bottom. It represents the percent change in traffic in the last hour as compared to yesterday's traffic at same time. A 0.5 result indicates a 50% difference in the traffic. The second query we are looking for drops of application usage. we compare traffic in the last hour to yesterday's traffic at the same time. We exclude Saturday, Sunday, and Monday because we expect large variability in the previous day's traffic at the same time. Once again adjust these values to fit your business operations model.
```KQL
let today = SigninLogs 
| where TimeGenerated > ago(1h) // Query failure rate in the last hour  
| project TimeGenerated, UserPrincipalName, AppDisplayName, status = case(Status.errorCode == "0", "success", "failure") 
// Optionally filter by a specific application 
//| where AppDisplayName == **APP NAME** 
| summarize success = countif(status == "success"), failure = countif(status == "failure") by bin(TimeGenerated, 1h) // hourly failure rate 
| project TimeGenerated, failureRate = (failure * 1.0) / ((failure + success) * 1.0) 
| sort by TimeGenerated desc 
| serialize rowNumber = row_number(); 
let yesterday = SigninLogs 
| where TimeGenerated between((ago(1h) – totimespan(1d))..(now() – totimespan(1d))) // Query failure rate at the same time yesterday 
| project TimeGenerated, UserPrincipalName, AppDisplayName, status = case(Status.errorCode == "0", "success", "failure") 
// Optionally filter by a specific application 
//| where AppDisplayName == **APP NAME** 
| summarize success = countif(status == "success"), failure = countif(status == "failure") by bin(TimeGenerated, 1h) // hourly failure rate at same time yesterday 
| project TimeGenerated, failureRateYesterday = (failure * 1.0) / ((failure + success) * 1.0) 
| sort by TimeGenerated desc 
| serialize rowNumber = row_number(); 
today 
| join (yesterday) on rowNumber // join data from same time today and yesterday 
| project TimeGenerated, failureRate, failureRateYesterday 
// Set threshold to be the percent difference in failure rate in the last hour as compared to the same time yesterday 
// Day variable is the number of days since the previous Sunday. Optionally ignore results on Sat, Sun, and Mon because large variability in traffic is expected. 
| extend day = dayofweek(now()) 
| where day != time(6.00:00:00) // exclude Sat 
| where day != time(0.00:00:00) // exclude Sun 
| where day != time(1.00:00:00) // exclude Mon 
| where abs(failureRate – failureRateYesterday) > 0.5 
```

```KQL
Let today = SigninLogs // Query traffic in the last hour 
| where TimeGenerated > ago(1h) 
| project TimeGenerated, AppDisplayName, UserPrincipalName 
// Optionally filter by AppDisplayName to scope query to a single application 
//| where AppDisplayName contains "Office 365 Exchange Online" 
| summarize users = dcount(UserPrincipalName) by bin(TimeGenerated, 1hr) // Count distinct users in the last hour 
| sort by TimeGenerated desc 
| serialize rn = row_number(); 
let yesterday = SigninLogs // Query traffic at the same hour yesterday 
| where TimeGenerated between((ago(1h) – totimespan(1d))..(now() – totimespan(1d))) // Count distinct users in the same hour yesterday 
| project TimeGenerated, AppDisplayName, UserPrincipalName 
// Optionally filter by AppDisplayName to scope query to a single application 
//| where AppDisplayName contains "Office 365 Exchange Online" 
| summarize usersYesterday = dcount(UserPrincipalName) by bin(TimeGenerated, 1hr) 
| sort by TimeGenerated desc 
| serialize rn = row_number(); 
today 
| join // Join data from today and yesterday together 
( 
yesterday 
) 
on rn 
// Calculate the difference in number of users in the last hour compared to the same time yesterday 
| project TimeGenerated, users, usersYesterday, difference = abs(users – usersYesterday), max = max_of(users, usersYesterday) 
| extend ratio = (difference * 1.0) / max // Ratio is the percent difference in traffic in the last hour as compared to the same time yesterday 
// Day variable is the number of days since the previous Sunday. Optionally ignore results on Sat, Sun, and Mon because large variability in traffic is expected. 
| extend day = dayofweek(now()) 
| where day != time(6.00:00:00) // exclude Sat 
| where day != time(0.00:00:00) // exclude Sun 
| where day != time(1.00:00:00) // exclude Mon 
| where ratio > 0.7 // Threshold percent difference in sign-in traffic as compared to same hour yesterday 
```

### Michael Lindsey
##### For Microsoft Defender External Attack Surface Management users that are using the published data connector to export data to Log Analytics or Sentinel, use the following query data to find IP Addresses within a range that are present in an attack surface and have an associated CVE ID in the previous 30 days.
```KQL
// IP WHOIS will often contain a NetRange value that is in this format, so we will expect that format:
//            NetRange:       13.64.0.0 - 13.107.255.255
let range = "13.64.0.0 - 13.107.255.255";
let c = split (range, "-");
let start = tostring (c [0]);
let end = tostring (c [1]);
EasmAssetWebComponent_CL
| where AssetType_s == "IP_ADDRESS"
| where not (WebComponentCves_s has "[]")
| where ipv4_compare (AssetName_s, start) >= 0 and ipv4_compare (AssetName_s, end) <= 0
| where WebComponentLastSeen_t between (ago (30d) .. now ())
| project AssetType_s,AssetName_s, WebComponentCves_s
| extend data = parse_json(WebComponentCves_s)
| mv-expand data
| project IP_Address = AssetName_s, CVE_ID = data.Cve, CWE_ID = data.Cwe, CVSS2Score = data.CvssScore, CVSS3Score = data.Cvss3Score
```

### Rudnei Oliveira
##### PowerShell or bash commands executed in Azure Cloud Shell. The query below will identify if any user started using Azure Cloud Shell to execute PowerShell or bash commands. If unexpected users are found, it should be further investigated.

```KQL
AzureActivity
| where CategoryValue == "Administrative"
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
| where ResourceGroup contains "CLOUD-SHELL-STORAGE"
| extend storageaccname = tostring(parse_json(Properties).resource)
| project OperationNameValue, Caller, CallerIpAddress, ResourceGroup
```

##### Sometimes adversaries will re-enable existing accounts and take control of them, rather than creating new accounts as a way to avoid detection. You can identify is a user has re-enabled a disabled user.
```KQL
AuditLogs 
| where OperationName == "Enable account" 
| extend userPrincipalName_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName) 
| extend ipAddress_ = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) 
| extend TargetUserEnabled = tostring(TargetResources[0].userPrincipalName) 
| project TimeGenerated, OperationName, UserThatEnableUser=userPrincipalName_, IPOrigin=ipAddress_, UserUpdated=TargetUserEnabled 
```

##### Parsing JSON can let you retrieve things like resource names from Azure Activity Logs. For instance, you can identify if someone creates a storage account to store and maintain malicious files within it.
```KQL
 AzureActivity 
| where CategoryValue == "Administrative" 
| where OperationNameValue contains "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE" 
| where ResourceGroup !contains "CLOUD-SHELL-STORAGE" 
| where ActivityStatusValue == "Success" 
| extend storageaccname = tostring(parse_json(Properties).resource) 
| project Caller, OperationNameValue, CallerIpAddress, ResourceGroup, storageaccname 
```

### Razi Rais
##### This KQL query, which generates insights into potential attack patterns based on a high volume of requests originating from IP Address, User Account, and other relevant factors, is exceptionally effective when executed hourly as an alert or as a part of a workbook to observe the pattern over a longer duration. The query is adaptable in that it permits you to pass column name dynamically, such as IPAddress, but modify it to another column, such as UserPrincipleName, without having to rewrite the query.
```KQL
let alertThreshold = 10.0; //Alert will be triggered when this threashold (%) will be crossed. Default is 10%
let duration = timespan(30d); //Duration (Azure Monitor only support alerts with duration looking pass data from 14 days) 
let totalRequestsWithRisk = (duration: timespan) {
    SigninLogs   
    | where TimeGenerated >= ago(duration)   
    | summarize total = count()
}; 
let eval = (columnName: string) {
    SigninLogs
    | where TimeGenerated >= ago(duration) 
    | summarize requestsSend = count() by column_ifexists(columnName, “”) 
    | project column_ifexists(columnName, “”), requestsSend    
    | extend total= toscalar(totalRequestsWithRisk(duration))    
    | extend percentage = round((toreal(requestsSend) / toreal(total)) * 100, 2)
    | where percentage > alertThreshold
    | project
        column_ifexists(columnName, “”),
        requests_send=requestsSend,
        total_requests=total,
        percentage_total = strcat(percentage, “%”),
        query_eval_window_days_hours_mins= format_timespan(duration, “d: h: m”) //days  
    | order by requests_send desc
};
eval(“UserPrincipalName”) //Can pass other column e.g. UserPrincipalName, etc
```

### Yong Rhee
##### Full outer joins can be useful for reporting, where you want the full set of data across all combined tables, such as reporting on antimalware signature, engine and platform versions in Microsoft Defender for Endpoint.
```KQL
let StartDate = ago(30d);
DeviceFileEvents 
| where Timestamp > StartDate
| where InitiatingProcessFileName =~ 'MpSigStub.exe' and InitiatingProcessCommandLine contains '/stub' and InitiatingProcessCommandLine contains '/payload'
| summarize Timestamp = arg_max(Timestamp, InitiatingProcessCommandLine) by DeviceId, DeviceName
| extend SplitCommand = split(InitiatingProcessCommandLine, ' ')
| extend EngineVersionLocation = array_index_of(SplitCommand, "/stub") + 1, DefinitionVersionLocation = array_index_of(SplitCommand, "/payload") + 1
| project Timestamp, DeviceName, DeviceId, AMEngineVersion = SplitCommand[EngineVersionLocation], AntivirusSignatureVersion = SplitCommand[DefinitionVersionLocation]
| join kind=fullouter (
    DeviceProcessEvents
    | where Timestamp > StartDate
    | where FileName =~ 'MsMpEng.exe' and FolderPath contains @"\Microsoft\Windows Defender\Platform\"
    | summarize arg_max(Timestamp, FolderPath) by DeviceId, DeviceName
    | project DeviceId, DeviceName, AMServiceVersion = split(FolderPath, '\\')[-2]
) on DeviceId
| project DeviceId, DeviceName, AMEngineVersion, AntivirusSignatureVersion, AMServiceVersion
```

##### You can detect anomalies in many different data sets, including email. Phishing attacks tend to be very short lived, with a sudden burst in activity, which is great to detect and visualize.
```KQL
let interval = 12h;
EmailEvents
| make-series MailCount = count() on Timestamp from ago(30d) to now() step interval by SenderFromDomain
| extend (flag, score, baseline) = series_decompose_anomalies(MailCount)
| mv-expand flag to typeof(int)
| where flag == 1 
| mv-expand score to typeof(double) // expand the score array to a double
| summarize MaxScore = max(score) by SenderFromDomain
| top 5 by MaxScore desc // Get the top 5 highest scoring domains
| join kind=rightsemi EmailEvents on SenderFromDomain
| summarize count() by SenderFromDomain, bin(Timestamp, interval)
| render timechart
```

### Sravani Salura
##### Performance troubleshooting. There are several queries you can use to look at your SQL server performance. The first query is looking for deadlock on the system that could lead to poor performance. The second query looks at the average CPU usage in the last hour. Consistently high averages could indicate a need to add additional resources.
```KQL
AzureMetrics 
| where ResourceProvider == "MICROSOFT.SQL" 
| where TimeGenerated >=ago(60min) 
| where MetricName in ('deadlock') 
| parse _ResourceId with * "/microsoft.sql/servers/" Resource // subtract Resource name for _ResourceId 
| summarize Deadlock_max_60Mins = max(Maximum) by Resource, MetricName
```

```KQL
AzureMetrics
| where ResourceProvider == "MICROSOFT.SQL" // /DATABASES
| where TimeGenerated >= ago(60min)
| where MetricName in ('cpu_percent') 
| parse _ResourceId with * "/microsoft.sql/servers/" Resource  // subtract Resource name for _ResourceId
| summarize CPU_Maximum_last15mins = max(Maximum), CPU_Minimum_last15mins = min(Minimum), CPU_Average_last15mins = avg(Average) by Resource , MetricName
```

##### Audit logs for table(s) and event type(s)
```KQL
// Search for audit logs for a specific table and event type DDL. Other event types are READ, WRITE, FUNCTION, MISC. It requires audit logs enabled. [https://docs.microsoft.com/azure/postgresql/concepts-audit]. 
AzureDiagnostics
| where ResourceProvider =="MICROSOFT.DBFORPOSTGRESQL" 
| where Category == "PostgreSQLLogs"
| where Message contains "AUDIT:" 
| where Message contains "table name" and Message contains "DDL"
```

##### Performance troubleshooting. Mointoring data for the last hour
```KQL
| where ResourceProvider == "MICROSOFT.SQL"
| where TimeGenerated >= ago(60min)
| where MetricName in ('log_write_percent')
| parse _ResourceId with * "/microsoft.sql/servers/" Resource// subtract Resource name for _ResourceId
| summarize Log_Maximum_last60mins = max(Maximum), Log_Minimum_last60mins = min(Minimum), Log_Average_last60mins = avg(Average) by Resource, MetricName
```

##### Performance troubleshooting. Wait status over the last hour, by logical server and database.
```KQL
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.SQL"
| where TimeGenerated >= ago(60min)
| parse _ResourceId with * "/microsoft.sql/servers/" LogicalServerName "/databases/" DatabaseName
| summarize Total_count_60mins = sum(delta_waiting_tasks_count_d) by LogicalServerName, DatabaseName, wait_type_s
```

### Krishna Venkit
##### Conditional access monitoring. These queries are useful to ensure that your conditional access policies are applying as expected. The first query will give you which applications that have sign-ins where there isn’t a conditional access policy applied. The second query will show which applications have the most conditional access failures, either the policy was not satisfied or access was blocked.
```KQL
SigninLogs
| where TimeGenerated > ago(1d)
| project ConditionalAccessStatus, AppDisplayName
| where ConditionalAccessStatus has "notapplied"
| summarize count() by AppDisplayName
| render piechart
```

```KQL
SigninLogs
| where TimeGenerated > ago(1d)
| project ConditionalAccessStatus, AppDisplayName
| where ConditionalAccessStatus has "failure"
| summarize count() by AppDisplayName
| render piechart
```
