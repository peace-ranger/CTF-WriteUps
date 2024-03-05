# Challenge Description
```
Name of the challenge says something.

Author : Samarth Kamble
FLAG FORMAT: VishwaCTF{}

Category: Web
Pts: 214
```

# Solution
This was a relatively easier challenge and as the name suggests, involved http header manipulation.
Upon visiting the challenge site, we were presented with the following message:
#### Step 1
![headers_step_1.png](images/headers_step_1.png)

It seems like we have to change the `User-Agent` header and set it to `lorbrowser`. I used Burp Browser, intercepted the request and sent it to repeater.
![[headers_step_2.png]]
#### Step 2
As we can see from the image, we got a new response which is a hint that we now need to set the `Referer` header to `https://vishwactf.com/`. Don't forget the trailing `/`. We will not get to the next step without it.
![[headers_step_3.png]]
#### Step 3
The new response hints to setting the `Date` header. Initially I tried to set the date like the usual format: `Tue, 05 Mar 2044 03:06:23 GMT`. But it didn't work for some reason. Then I just set the date to `2044` and it worked!
![[headers_step_4.png]]
#### Step 4
I searched online and found that the `Upgrade-Insecure-Requests` header is used to set preference for an encrypted and authenticated response. So I set the value of the header to `10` and got the next response.
![[CTF Write-Ups/2024/VishwaCTF/images/headers_step_5.png]]
#### Step 5
This last step took me the longest. Not because it was hard, but because the author made it unnecessarily cryptic. What on earth is this `Nine times (9)` mean?!! Turned out its `999999999`!!! After two hours of trying I found it out. Most of the participants were lost at it!  I mean why you make challenges difficult by making them cryptic! Should focus on making it technically difficult, not through the wordings! Anyways, enough ranting. Oh, btw, the header in this step is `Downlink` which can be easily found by searching for "approximate bandwidth of the clients connection to the server". We can see the flag after this step. Phew!
![[headers_step_5 1.png]]

## Flag
`VishwaCTF{s3cret_sit3_http_head3rs_r_c0o1}`
