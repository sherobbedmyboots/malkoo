# Using the Airwatch API

Airwatch is an Enterprise Mobility Management (EMM) tool used to manage wireless networks, mobile devices, and other mobile services in our environment.  The [AIRWATCHmodule](../scripts/Modules/AIRWATCHmodule.psm1) can be used to interact with the Airwatch API and gather user, system, and network information to support monitoring and investigations.

This document walks through setup and basic use of the Airwatch API using the AIRWATCHmodule:

- [Setup](#setup)
- [Operation](#operation)
- [Groups](#Groups)
- [Users](#Users)
- [Devices](#searching-devices)
- [Applications](#searching-applications)
- [List of APIs](#list-of-apis)


## Setup

Create a ticket like [this one]() to request access:

![](images/Using%20the%20Airwatch%20API/image002.png)<br><br>


When it's approved, import the [Airwatch Module](../scripts/Modules/AIRWATCHmodule.psm1):

```powershell
Import-Module AIRWATCHmodule
```

<br>

Get a password for your admin account:

![](images/Using%20the%20Airwatch%20API/image001.png)<br><br>

Use the `New-AWApiPassword` function to securely store this password so the AIRWATCHmodule can include it in each API call:

![](images/Using%20the%20Airwatch%20API/image006.png)<br><br>

This stores your password to `$env:USERPROFILE\.airwatch.txt` file via securestring:

![](images/Using%20the%20Airwatch%20API/image007.png)<br><br>

Then acquire an API key and store it with the following:

```powershell
Read-Host "Enter API key" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$env:USERPROFILE\.airwatch_api.txt"
```

<br>

This will store the API key to `$env:USERPROFILE\.airwatch_api.txt` via securestring:

![](images/Using%20the%20Airwatch%20API/image013.png)<br><br>

Now you're ready to make API calls.


## Operation

The Airwatch API provides endpoints for different functions.  Here are some examples:

|API Name|API Endpoint|
|-|-|
|API Information|`system/info`|
|Search a User|`system/users/search?user={username}`|
|Search Play Store for Applications|`mam/apps/playstore/search`|
|Retrieve Device Associated Smart Groups |`mdm/devices/{id}/smartgroups`|
|Fetch Enrollment Users in an Organization Group|`system/groups/{id}/users`|

<br>

Each API call is directed to an endpoint.  The `Get-AWApi` function takes an endpoint as an argument and makes an API call to it:

![](images/Using%20the%20Airwatch%20API/image008.png)<br><br>

You can then read or capture the objects that are returned:

![](images/Using%20the%20Airwatch%20API/image009.png)<br><br>

Different parameters can be used to target specific properties:

![](images/Using%20the%20Airwatch%20API/image014.png)<br><br>

Here are several examples of functions that use a combination of different APIs to quickly collect information about groups, users, devices, or applications:

- [Groups](#groups)
- [Users](#searching-users)
- [Devices](#searching-devices)
- [Applications](#searching-applications)


## Groups

Run the `Get-AWGroupInfo` function without any arguments to see all groups:

![](images/Using%20the%20Airwatch%20API/image032.png)<br><br>


Get details of a group using the group ID, group name, or group type:

![](images/Using%20the%20Airwatch%20API/image030.png)<br><br>

The API matches any group that *contains* the argument provided.  For example, searching for the `InfoPass` string returns four different groups:

![](images/Using%20the%20Airwatch%20API/image035.png)<br><br>

See a group's tags:

![](images/Using%20the%20Airwatch%20API/image031.png)<br><br>

And roles:

![](images/Using%20the%20Airwatch%20API/image033.png)<br><br>

And custom attributes:

![](images/Using%20the%20Airwatch%20API/image036.png)<br><br>

Show a group's users (Don't do this with a group containing thousands of users as it will lock up... Check the `UserCount` first):

![](images/Using%20the%20Airwatch%20API/image034.png)<br><br>

## Users

Search for users by first name, last name, email address, or username using the `Get-AWUserInfo` function:

|Method|Command|
|-|-|
|By first name|`Get-AWUserInfo -firstname bob`|
|By last name|`Get-AWUserInfo -lastname smith`|
|By email|`Get-AWUserInfo -email bob.smith@domain.com`|
|By username|`Get-AWUserInfo -username bsmith`|

<br>

Search a user with an email address:

![](images/Using%20the%20Airwatch%20API/image010.png)<br><br>

If the user has a device, it shows the device ID of the device:

![](images/Using%20the%20Airwatch%20API/image011.png)<br><br>

Capture into an object and list all devices for this user:

![](images/Using%20the%20Airwatch%20API/image015.png)<br><br>

With device IDs we can gather more information about the device.


## Searching Devices

Search devices and their product assignment information with the `Get-AWDeviceInfo` function:

![](images/Using%20the%20Airwatch%20API/image005.png)<br><br>

Drill down into each object for additional information such as installed and pending products:

![](images/Using%20the%20Airwatch%20API/image004.png)<br><br>

Or all applications installed on device:

![](images/Using%20the%20Airwatch%20API/image012.png)<br><br>

See profile details for a device:

![](images/Using%20the%20Airwatch%20API/image016.png)<br><br>

Notes:

![](images/Using%20the%20Airwatch%20API/image028.png)<br><br>

And certificates:

![](images/Using%20the%20Airwatch%20API/image017.png)<br><br>

User information:

![](images/Using%20the%20Airwatch%20API/image018.png)<br><br>

Smart groups:

![](images/Using%20the%20Airwatch%20API/image019.png)<br><br>


## Searching Applications

The `Get-AWApplicationInfo` function can be used to obtain information about applications.  Run it with no arguments to list all applications:

![](images/Using%20the%20Airwatch%20API/image037.png)<br><br>

To see information for an individual application, specify the name:

![](images/Using%20the%20Airwatch%20API/image025.png)<br><br>

In this case, there are two versions of the application:

![](images/Using%20the%20Airwatch%20API/image039.png)<br><br>

See supported devices and smart groups:

![](images/Using%20the%20Airwatch%20API/image026.png)<br><br>

Get details about a smart group:

![](images/Using%20the%20Airwatch%20API/image021.png)<br><br>

Get a list of applications for that smart group:

![](images/Using%20the%20Airwatch%20API/image022.png)<br><br>

Get a list of devices in that smart group:

![](images/Using%20the%20Airwatch%20API/image023.png)<br><br>

Get application details from Google Play, Windows, and Apple Stores:

![](images/Using%20the%20Airwatch%20API/image024.png)<br><br>

Show application URLs:

![](images/Using%20the%20Airwatch%20API/image027.png)<br><br>




## List of APIs

Here are some read-only APIs that can be called individually or as part of a function:

### Organization Group Management

|API Name|API Endpoint|
|-|-|
|Group Information|`system/groups/{id}`|
|Group Child Details|`system/groups/{id}/children`|
|Search Org Groups|`system/groups/search?name={name}`<br>`system/groups/search?type={type}`<br>`system/groups/search?groupid={groupid}`|
|Group Admins|`system/groups/{id}/admins`|
|Group Users|`system/groups/{id}/users`|
|Group Roles|`system/groups/{id}/roles`|
|Group Tags|`system/groups/{id}/tags`|
|Device Counts|`system/groups/devicecounts?organizationgroupid={organizationgroupid}`<br>`system/groups/devicecounts?seensince={seensince}`<br>`system/groups/devicecounts?seentill={seentill}`|
|Custom Attributes|`system/groups/{ogid}/CustomAttributes`|

<br>

### User Group Management

|API Name|API Endpoint|
|-|-|
|System Information|`system/info`|
|User Details|`system/users/{id}`|
|Search Users|`system/users/search?firstname={firstname}`<br>`system/users/search?lastname={lastname}`<br>`system/users/search?email={email}`<br>`system/users/search?locationgroupId={locationgroupid}`<br>`system/users/search?role={role}`<br>`system/users/search?username={username}`|
|Search Admins|`system/admins/search?firstname={firstname}`<br>`system/admins/search?lastname={lastname}`<br>`system/admins/search?email={email}`<br>`system/admins/search?locationgroupId={locationgroupid}`<br>`system/admins/search?role={role}`<br>`system/admins/search?username={username}`|
|Enrolled Devices|`system/users/enrolleddevices/search?organizationgroupid={organizationgroupid}`<br>`system/users/enrolleddevices/search?organizationgroup={organizationgroup}`<br>`system/users/enrolleddevices/search?platform={platform}`<br>`system/users/enrolleddevices/search?customattributes={customattributes}`<br>`system/users/enrolleddevices/search?serialnumber={serialnumber}`<br>`system/users/enrolleddevices/search?seensince={seensince}`<br>`system/users/enrolleddevices/search?seentill={seentill}`<br>`system/users/enrolleddevices/search?enrolledsince={enrolledsince}`<br>`system/users/enrolleddevices/search?enrolledtill={enrolledtill}`|
|Enrolled Devices|`system/users/registereddevices/search?organizationgroupid={organizationgroupid}`<br>`system/users/registereddevices/search?organizationgroup={organizationgroup}`<br>`system/users/registereddevices/search?platform={platform}`<br>`system/users/registereddevices/search?customattributes={customattributes}`<br>`system/users/registereddevices/search?assetnumber={assetnumber}`<br>`system/users/registereddevices/search?seensince={seensince}`<br>`system/users/registereddevices/search?seentill={seentill}`|

<br>

### Mobile Device Management

|API Name|API Endpoint|
|-|-|
|Device Information|`mdm/devices/{id}`|
|Device Apps|`mdm/devices/{id}/apps`|
|Device Certificates|`mdm/devices/{id}/certificates`|
|Device Smart Groups|`mdm/devices/{id}/smartgroups`|
|Device Notes|`mdm/devices/{id}/notes`|
|Compliance Details|`mdm/devices/{id}/compliance`|
|Content Details|`mdm/devices/{id}/content`|
|Network Information|`mdm/devices/{id}/network`|
|Profile Details|`mdm/devices/{id}/profile`|
|User Details|`mdm/devices/{id}/user`|
|Smart Group Details|`mdm/smartgroups/{id}`|
|Security Information|`mdm/devices/{id}/security`|
|Device Details|`mdm/devices/search?user={user}`<br>`mdm/devices/search?model={model}`<br>`mdm/devices/search?platform={platform}`<br>`mdm/devices/search?lastseen={lastseen}`<br>`mdm/devices/search?ownership={ownership}`<br>`mdm/devices/search?Igid={Igid}`<br>`mdm/devices/search?compliantstatus={compliantstatus}`<br>`mdm/devices/search?seensince={seensince}`<br>|

<br>

### Mobile Application Management

|API Name|API Endpoint|
|-|-|
|Search Apps|`mam/apps/search?type={type}`<br>`mam/apps/search?applicationtype={applicationtype}`<br>`mam/apps/search?applicationname={applicationname}`<br>`mam/apps/search?category={category}`<br>`mam/apps/search?locationgroupid={locationgroupid}`<br>`mam/apps/search?bundleid={bundleid}`<br>`mam/apps/search?platform={platform}`<br>`mam/apps/search?model={model}`<br>`mam/apps/search?status={status}`|
|Search Store for Apps<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Play store<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Windows App Store<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Apple Store|<br>`mam/apps/playstore/search?appname={name}`<br>`mam/apps/windowsstore/search?appname={name}`<br>`mam/apps/applestore/search?appname={name}`|
|App Details|`mam/apps/{udid}/{appId}/{appType}/{deviceType}`<br>`mam/apps/{apptype}/{applicationid}`|
|App Group Details|`mam/apps/appgroups/{appgroupid}`
|Assigned Devices|`mam/apps/{apptype}/{applicationid}/devices`|
|App Groups |`mam/apps/appgroups/search`|
|Purchased App|`mam/apps/purchased/search`|
