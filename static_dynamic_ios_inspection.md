# Static / Dynamic iOS app inspection

<!-- TOC depthfrom:2 depthto:3 updateonsave:false withlinks:true -->

- [Make apps from AppStore inspectable](#make-apps-from-appstore-inspectable)
- [Logs](#logs)
- [Files inside of IPA](#files-inside-of-ipa)
- [Files on Device](#files-on-device)
    - [iOS file structure](#ios-file-structure)
- [Build information](#build-information)
- [Symbols](#symbols)
- [Strings](#strings)
- [Applesign](#applesign)
- [Sideload iOS app](#sideload-ios-app)
- [Troubleshoot codesign / iOS Deploy](#troubleshoot-codesign--ios-deploy)
- [Frida-Server](#frida-server)
- [Frida-Gadget](#frida-gadget)
- [Frida basics](#frida-basics)
- [Frida's --eval flag](#fridas---eval-flag)
- [Frida Intercepter](#frida-intercepter)
- [Frida-Trace](#frida-trace)
- [Bypass anti-Frida checks](#bypass-anti-frida-checks)
- [Cookies](#cookies)
- [Change iOS Version](#change-ios-version)
- [LLVM Instrumentation](#llvm-instrumentation)

<!-- /TOC -->

## Make apps from AppStore inspectable

#### Get App Store iPAs

- Install Apple's utility [Apple Configurator 2](https://apps.apple.com/us/app/apple-configurator-2/id1037126344?mt=12) from macOS store
- Install the target iOS app on the target device
- Then open `Apple Configurator 2` and "sign in" with the same Apple account used on the target device
- Sign-out and sign-in to refresh the known app list
- Right click on device and select `Add/Apps`
- Don't install the app - go to `Finder` and:

---
>`~/Library/Group Containers/K36BKF7T3D.group.com.apple.configurator/Caches/Assets/TemporaryItems/MobileApps/`

---
Referenced [article](https://medium.com/@b0661064248/how-can-i-get-ipa-of-any-app-which-is-available-on-app-store-3a403be7b028).

#### Unzip the IPA file to reveal the Payload folder

`unzip myApp.ipa`

#### Decrypt iPA

Mandatory if you want to find good strings, debug the app or repackage the iPA.

[frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump)

#### Check AppStore binary is encrypted

```bash
otool -l foobar | grep -i LC_ENCRYPTION -B1 -A4
Load command 12
          cmd LC_ENCRYPTION_INFO
      cmdsize 20
     cryptoff 16384
    cryptsize 12910592
      cryptid 1
--
--
Load command 12
          cmd LC_ENCRYPTION_INFO_64
      cmdsize 24
     cryptoff 16384
    cryptsize 14041088
      cryptid 1
```

## Logs

#### Simulator filter on Debug String

`xcrun simctl spawn booted log stream --level=debug | grep App_Debug_String`

#### Simulator filter on App Name

`xcrun simctl spawn booted log stream --predicate 'processImagePath endswith "MyAppName"'`

#### Real device

`idevicesyslog -u <DeviceID> | myPipedProgram`

## Files inside IPA

#### Files big files inside unzipped IPA

`find Payload -size +2M`

#### Files that were mistakingly shipped inside of App Bundle

`find . -name '*.json' -or -name '*.txt'`

#### Check for ReactNative

`find . -name main.jsbundle`

#### Check for Certificates

`find . -name '*.crt' -or -name '*.cer' -or -name '*.der'`

#### Property lists in Payload. Recursive search

`find Payload/ -name '*.plist'`

#### Provisioning Profiles

`find . -name '*.mobileprovision'`

#### Dynamically linked frameworks

`find . -name '*.framework'`

#### Locally linked javascript

`find Payload -name '*.js'`

#### Search all plist files for a value

`find . -name '*.plist' | xargs grep "LSApplicationQueriesSchemes"`

#### Search all plist files for Device Permissions or App Transport Security

`find . -name '*.plist' | xargs grep "NS"`

#### Search all files using only grep

`grep "LSApplicationQueriesSchemes" . -R`

#### Recursive search all files using grep inside an .app folder

```bash
grep "Requires" foobar.app -R
foobar.app/Info.plist:    <key>UIRequiresFullScreen</key>
foobar.app/Info.plist:    <key>LSRequiresIPhoneOS</key>
```

#### Inspect any device logs you find

`grep -i -B 10 'error'`

## Files on iOS device

### iOS file structure

```bash
# Sandbox. Look here for Cookies, json files, etc
/var/mobile/Containers/Data/Application/[GUID given at install time]/

# Folder of App Bundle that was installed. Executables, frameworks, fonts, CSS, html. NIB files.
/private/var/containers/Bundle/Application/[GUID given at app install]/foo.app

# App executable
/private/var/containers/Bundle/Application/[GUID given at app install]/foo.app/foo
```

#### Inspect sandboxed data

```bash
cd /private/var/mobile/Containers/Data/Application/
ls -lrt  // Your freshly installed IPA is at the bottom of list
cd [app guid]/Documents/
cd [app guid]/Library/
```

#### Databases to pull off a device

```bash
/private/var/Keychains
TrustStore.sqlite3
keychain-2.db
pinningrules.sqlite3
```

#### File sharing

```bash
# Extract IPA (whether App Store encrypted or not)
scp -r -P 2222 root@localhost:/var/containers/Bundle/Application/<app GUID>/hitme.app ~/hitme.app

# Different to SSH, the uppercase P for Port with SCP. Order important.
scp -P 2222 root@localhost:/var/root/overflow.c localfilename.c

# from Jailbroken device to local machine
# Caution:no space after the root@localhost: Otherwise you copy the entire filesystem!
scp -P 2222 root@localhost:/private/var/mobile/Containers/Data/Application/<App GUID>/Library/Caches/Snapshots/com.my.app

# from local machine to remote Jailbroken device
scp -P 2222 hello.txt root@localhost:/var/root/
```

## Build information

#### Check platform

`lipo -info libprogressbar.a`

#### Check for build errors

`jtool -arch arm64 -L <binary inside app bundle>`

#### Check minimum iOS version & restrict linker flag

`jtool -arch arm64 -l <binary inside app bundle>`

#### Check Load Commands

`rabin2 -H playground`

#### Sections of the Binary

`objdump -macho -section-headers Payload/myApp.app/myApp`

#### iOS app entitlements

```bash
codesign -d --entitlements :- Payload/MyApp.app
jtool -arch arm64 --ent <binary inside app bundle>
```

#### Simple Permissions check

`cat Payload/*/Info.plist | grep -i NS`

#### Device Support

<https://gist.github.com/adamawolf/3048717>

#### Check binary was stripped

`rabin2 -I -a arm_64 <binary inside app bundle> | grep -E 'stripped|canary'`

#### Check Position Independent Code set

`rabin2 -I -a arm_64 <binary inside app bundle> | grep -E 'pic|bits`

#### Check for Bitcode enabled

```bash
otool -l libprogressbar.a | grep __LLVM
otool -arch arm64 -l tinyDynamicFramework | grep __LLVM
// Remember this command won't work on a locally built Simulator / iPhone app. Bitcode happens after setting `Archive`
```

## Symbols

#### nm

`nm libprogressbar.a | less`

#### rabin2

`rabin2 -s file`

#### radare2

`is~FUNC`

## Strings

#### Check URLs

```bash
strings <binary inside app bundle>  | grep -E 'session|https'
strings <binary inside app bundle>  | grep -E 'pinning'
rabin2 -qz <binary inside app bundle>                                   // in Data Section
rabin2 -qzz <binary inside app bundle>                                  // ALL strings in binary
​
jtool -dA __TEXT.__cstring c_playground
Dumping C-Strings from address 0x100000f7c (Segment: __TEXT.__cstring)..
Address : 0x100000f7c = Offset 0xf7c
0x100000f7c: and we have a winner @ %ld\r
0x100000f98: and that's a wrap folks!\r
```

## Applesign

`Applesign` is a wrapper around `Codesigning` tools from Apple.

```
npm install -g applesign

#### Create provisioning file

First, you want to get hold of an `embedded.mobileprovision` file.  Fear not, this step is simple.

Open `Xcode` and select `File/New/Project/Swift` and call it `foobar`.  Select `build` for Generic (ARM) Device.  Do not select a simulator. This is normally enough.  

You don’t need to `run` the app unless want to automagically add your device’s UUID to the Provisioning Profile.  

Now right click on the `/Product/foobar.app` - in the left hand view pane - and select "show in finder".  If you look inside the folder ( remember `foobar.app` is a folder ) you will find a fresh `embedded.mobileprovision`.  This contains the uniques IDs and an expiry date for the developer profile associated to the app.

#### Read the Provisioning Profile

Ensure your device ID is in the profile and the profile is fresh.

`security cms -D -i embedded.mobileprovision`

#### List all of your Code signing identities

```bash
security find-identity -v -p codesigning
export CODESIGNID=<GUID>
```

#### Resign iPA: change bundle ID

`applesign -7 -i ${CODESIGNID} --bundleid funky-chicken.resigned`

#### Resign iPA: set app to debuggable with custom provisioning file ( default )

`applesign -7 -i ${CODESIGNID} -m embedded.mobileprovision unsigned.ipa -o ready.ipa`

#### Resign the iPA: set output IPA name. Won't be debuggable, if it is a App Store app

`applesign -7 -i ${CODESIGNID} myapp.ipa -o resigned.ipa`

#### Speed up repackaging

```bash
rm -v unsigned.ipa | rm -v ready.ipa | 7z a unsigned.ipa Payload

// Keep original Bundle ID
applesign -7 -i ${CODESIGNID} -m embedded.mobileprovision unsigned.ipa -o ready.ipa

// Set Bundle ID
// applesign -7 -i ${CODESIGNID} -b yd.com.rusty.repackaged -m embedded.mobileprovision unsigned.ipa -o ready.ipa

ios-deploy -b ready.ipa
```

## Sideload iOS app

```bash
ios-deploy -b myapp-resigned.ipa        // defaults to send over wifi
ios-deploy -b -W myapp-resigned.ipa     // uses USB
ios-deploy -B | grep -i funky           // list Bundle IDs
```

## Troubleshoot codesign / iOS Deploy

Title  | Detail  
--|--
Missing Device ID  | Check Provisioning Profile (`embedded.mobileprovision`) included device's UUID
Check code sign key has not expired | Code Signing keys expire. The timeframe for the paid iOS Developer license is one-year. For the free developer signing key, it is much shorter.
Wrong Code-Signing Key  |  check the Code Signing Key was NOT an `iPhone Distribution key`
Code Signing Keys Match  |  check the `Code Signing Key` used when creating the `Provisioning Profile` matched the `Code Signing Key` selected when repackaging and code signing.
XCode check  |  When generating an app - to get hold of `embedded.mobileprovision` file - remember the `Code signing` options are different for each Project Target and ProjectTests.
Delete Old Apps  |  check no old app is installed on the phone [ that was signed with a different key ] but has the same Bundle ID.
Entitlements overload |  You can have a `Provisioning Profile` (embedded.mobileprovision) that contained more `Capabilities` than the app you are re-signing.
Clone Entitlements  | When the app is complicated, with many entitlements, sometimes it is easier just to `--clone-entitlements` with `Applesign`.
Wrong Bundle ID  | When you add specific `Entitlments` you need a unique Bundle ID.  Check whether you need to change Bundle ID when re-signing.
Network settings | `Settings\General\Profiles and Device Management` to trust the Developer Profile and App.  This won't happen if you are manually proxying or setting a local DNS server., when installing with `iOS-deploy`.

---

If none of the above work open `Console.app` on macOS.  Select your device and set `process:mobile_installation_proxy` in the `Search Bar`.  This will give details behind the sideloaded IPA error message.

## Frida-Server

#### list available devices

`frida-ls-devices`

#### connect to cat by name

`frida -n cat`

#### Force open foobar

`frida -f foobar`

#### open foobar over usb and force start. starts app running

`frida -U -f foobar --no-pause`

#### list processes and bundle ID from USB connected device

`frida-ps -Uai`

#### keep updated

`pip3 install --upgrade frida`

#### get the target app's process ID from USB connected device

`frida-ps -U | grep -i myapp`

#### Run script and quit Frida

`frida -U -f foobar --no-pause -q --eval 'console.log("Hi Frida");'`

## Frida-Gadget

Since `Frida version ~12.7`, it was quick and simple to Frida on a Jailed device:

#### Get Frida-Gadget

<https://github.com/frida/frida/releases>

#### Unzip

`gunzip frida-gadget-12.xx.xx-ios-universal.dylib.gz`

#### Create directory for Frida-Gadget

`mkdir -p ~/.cache/frida`

#### Move Frida-Gadget

`cp frida-gadget-12.xx.xx-ios-universal.dylib ~/.cache/frida/gadget-ios.dylib`

#### Invoke Frida-Gadget on Clean device

`frida -U -f funky-chicken.debugger-challenge`

## Frida basics

```bash
frida -U "My App"               // Attach Frida to app over USB

Process.id
419

Process.getCurrentThreadId()
3843

var b = "hello frida"

console.log(b)
"hello frida"

c = Memory.allocUtf8String(b)
"0x1067ec510"

Memory.readUtf8String(c)
"hello frida"

console.log(c)
0x1067ec510

console.log(c.readUtf8String(5))
hello

console.log(c.readUtf8String(11))
hello frida

ptrToC = new NativePointer(c);
"0x1067ec510"

console.log(ptrToC)
0x1067ec510

console.log(ptrToC.readCString(8))
hello fr

Memory.readUtf8String(ptrToC)
"hello frida"
```

#### Frida - Objective-C

Objective-C's syntax includes the `:` and `@` characters.  These characters were not used in the `Frida Javascript API`.

```bash
// Attach to playground process ID
frida -p $(ps -ax | grep -i -m1 playground |awk '{print $1}')

ObjC.available
true

ObjC.classes.UIDevice.currentDevice().systemVersion().toString()
"11.1"

ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()

ObjC.classes.UIWindow.keyWindow().toString()
RET: <WKNavigation: 0x106e165c0>

// shows Static Methods and Instance Methods
ObjC.classes.NSString.$ownMethods

ObjC.classes.NSString.$ivars

var myDate = ObjC.classes.NSDate.alloc().init()

console.log(myDate)
2019-04-19 19:03:46 +0000

myDate.timeIntervalSince1970()
1555700626.021566

myDate.description().toString()
"2019-04-19 19:03:46 +0000"

var a = ObjC.classes.NSUUID.alloc().init()

console.log(a)
4645BFD2-94EE-413D-9CE5-8982D41ED6AE

a.UUIDString()
{
    "handle": "0x7ff3b2403b20"
}
a.UUIDString().toString()
"4645BFD2-94EE-413D-9CE5-8982D41ED6AE"
```

#### NSString

```bash
var b = ObjC.classes.NSString.stringWithString_("foo");

b.isKindOfClass_(ObjC.classes.NSString)
true

b.isKindOfClass_(ObjC.classes.NSUUID)
false

b.isEqualToString_("foo")
true

b.description().toString()
"foo"

var c = ObjC.classes.NSString.stringWithFormat_('foo ' + 'bar ' + 'lives');

console.log(c)
foo bar lives
```

#### NSURL

```bash
var url = ObjC.classes.NSURL.URLWithString_('www.foobar.com')

console.log(url)
www.foobar.com

url.isKindOfClass_(ObjC.classes.NSURL)
true

console.log(url.$class)
NSURL
```

#### Frida from NSString to NSData back to Hex String

```bash
var b = ObjC.classes.NSString.stringWithString_("foo");

var d = ObjC.classes.NSData
d = b.dataUsingEncoding_(1)			//	NSASCIIStringEncoding = 1, NSUTF8StringEncoding = 4,

console.log(d)
<666f6f>					//	This prints the Hex value "666f6f = foo"

d.$className
"NSConcreteMutableData"

var x = d.CKHexString()				//	get you the Byte array as a Hex string

console.log(x)
666f6f

x.$className
"NSTaggedPointerString"

var newStr = ObjC.classes.NSString.stringWithUTF8String_[d.bytes]

```

#### Frida with xCode Simulator

```bash
// demoapp is the iOS app name
myapp=$(ps x | grep -i -m1 demoapp | awk '{print $1}')
frida-trace -i "getfsent*" -p $myapp

// Connect to process with Frida script
frida --codeshare mrmacete/objc-method-observer -p 85974
```

#### Frida find Modules

```frida
Process.enumerateModules()      
// this will print all loaded Modules

Process.findModuleByName("libboringssl.dylib")
{
    "base": "0x1861e2000",
    "name": "libboringssl.dylib",
    "path": "/usr/lib/libboringssl.dylib",
    "size": 712704
}

Process.findModuleByAddress("0x1c1c4645c")
{
    "base": "0x1c1c2a000",
    "name": "libsystem_kernel.dylib",
    "path": "/usr/lib/system/libsystem_kernel.dylib",
    "size": 200704
}
```
#### Find Address and Module of function name ( Export )
```
DebugSymbol.fromAddress(Module.findExportByName(null, 'strstr'))
{
    "address": "0x183cb81e8",
    "fileName": "",
    "lineNumber": 0,
    "moduleName": "libsystem_c.dylib",
    "name": "strstr"
}
```
#### Find Address of Export and use Address to find Module
```
Module.findExportByName(null, 'strstr')
"0x183cb81e8"

Module.getExportByName(null,'strstr')
"0x183cb81e8"

Process.findModuleByAddress("0x183cb81e8")
{
    "base": "0x183cb6000",
    "name": "libsystem_c.dylib",
    "path": "/usr/lib/system/libsystem_c.dylib",
    "size": 516096
}
```

#### Exports inside a Module

```frida
a = Process.findModuleByName("Reachability")
a.enumerateExports()
....
{
    "address": "0x102fab020",
    "name": "ReachabilityVersionString",
    "type": "variable"
},
{
    "address": "0x102fab058",
    "name": "ReachabilityVersionNumber",
    "type": "variable"
}
....
...
..
```

## Frida's --eval flag

#### Enumerate all Exports, grepping for one function, and quit

```javascript
frida -U -f funky-chicken.debugger-challenge --no-pause -q --eval 'var x={};Process.enumerateModulesSync().forEach(function(m){x[m.name] = Module.enumerateExportsSync(m.name)});' | grep -B 1 -A 1 task_threads

            "address": "0x1c1c4645c",
            "name": "task_threads",
            "type": "function"
```

#### Search for Module, with the Exports' Address

```javascript
frida -U -f funky-chicken.debugger-challenge --no-pause -q --eval 'var x={};Process.findModuleByAddress("0x1c1c4645c");'

{
    "base": "0x1c1c2a000",
    "name": "libsystem_kernel.dylib",
    "path": "/usr/lib/system/libsystem_kernel.dylib",
    "size": 200704
}
```

## Frida Intercepter

```javascript
[objc_playground]-> var a = ObjC.classes.NSString.stringWithString_("foo");

[objc_playground]-> a.superclass().toString()
"NSString"

[objc_playground]-> a.class().toString()
"NSTaggedPointerString"

// PASTE THIS CODE INTO THE FRIDA INTERFACE...
Interceptor.attach(ObjC.classes.NSTaggedPointerString['- isEqualToString:'].implementation, {
    onEnter: function (args) {
      var str = new ObjC.Object(ptr(args[2])).toString()
      console.log('[+] Hooked NSTaggedPointerString[- isEqualToString:] ->' , str);
    }
});

// TRIGGER YOUR INTERCEPTOR
[objc_playground_2]-> a.isEqualToString_("foo")
[+] Hooked NSTaggedPointerString[- isEqualToString:] -> foo
1   // TRUE
[objc_playground_2]-> a.isEqualToString_("bar")
[+] Hooked NSTaggedPointerString[- isEqualToString:] -> bar
0   // FALSE
```

#### Frida Intercepter - monitor file open

```javascript
// frida -U -l open.js --no-pause -f com.yd.demoapp

// the below javascript code is the contents of open.js

var targetFunction = Module.findExportByName("libsystem_kernel.dylib", "open");

Interceptor.attach(targetFunction, {
    onEnter: function (args) {
        const path = Memory.readUtf8String(this.context.x0);
        console.log("[+] " + path)
    }
});
```

#### Frida Intercepter - monitor Swift Mangled function

```javascript
try {

    var targetFunctPtr = Module.findExportByName("YDAppModule", "$s9YDAppModule17ConfigC33publicKeyVerifyCertsSayypGvpfi");
    if (targetFunctPtr == null) {
        throw "[*] Target function not found";
    }
    Interceptor.attach(targetFunctPtr, {
        onLeave: function(retval) {
            var array = new ObjC.Object(retval);
            console.log('[*]ObjC Class Type:\t' + array.$className);
            return retval;
        }
    });
    console.log("[*] publicKeyVerifyCertificates called ");
}
catch(err){
    console.log("[!] Exception: " + err.message);
}
```

## Frida-Trace

```javascript
frida-trace --v                                                                   // check it works
frida-trace --help                                                                // excellent place to read about Flags
frida-trace -f objc_playground                                                    // spawn and NO trace
frida-trace -m "+[NSUUID UUID]" -U "Debug CrackMe"                                // trace ObjC UUID static Class Method
frida-trace -m "*[ComVendorDebugger* *]" -U -f com.robot.demo.app                 // ObjC wildcard trace on Classes
frida-trace -m "*[YDDummyApp.UserProfileMngr *]" -U -f com.robot.demo.app         //  Trace mangled Swift functions
Instrumenting functions...                                                                
           /* TID 0x403 */
  1128 ms  -[YDDummyApp.UserProfileMngr init]
  1130 ms  -[YDDummyApp.UserProfileMngr .cxx_destruct]


frida-trace -i "getaddrinfo" -i "SSLSetSessionOption" -U -f com.robot.demo        // trace C function on iOS
frida-trace -m "*[*URLProtection* *]" -U -f com.robot.demo                        // for https challenge information
frida-trace -m "*[NSURLSession* *didReceiveChallenge*]" -U -f com.robot.demo      // check whether https check delegate used
frida-trace -U -f com.robot.demo.app -I libsystem_c.dylib                         // Trace entire Module.  Bad idea!
frida-trace -p $myapp -I UIKit                                                    // Trace UIKit Module.  Bad idea.
frida-trace -f objc_playground -I CoreFoundation                                  // Trace CoreFoundation Module.  Terrible idea.
frida-trace -I YDRustyKit -U -f com.yd.mobile                                     // Trace my own module.
frida-trace -m "-[NSURLRequest initWithURL:]" -U -f com.robot.demo                // Get app files and APIs
frida-trace -m "-[NSURL initWithString:]" -U -f com.robot.demo                    // find the API endpoints
frida-trace -m "*[NSURL absoluteString]" -U -f com.robot.demo                     // my favorite of these
```

Edit the Frida-Trace auto-generated, template file.

```javascript
onEnter: function (log, args, state) {
  log("-[NSURLRequest initWithURL:" + args[2] + "]");
  var str = new ObjC.Object(ptr(args[2])).toString()
  console.log('[*] ' , str);
},

// results
[*] https://secretserver.nl/SignIn
```

#### Frida-Trace strcpy()

```bash
frida-trace -i "*strcpy" -f hitme aaaa bbbb
Instrumenting functions...                                              
_platform_strcpy: Loaded handler at "/.../__handlers__/libSystem.B.dylib/_platform_strcpy.js"
Started tracing 1 function. Press Ctrl+C to stop.                       
```

Edit the auto-generated, template Javascript file.

```javascript
-----------
onEnter: function (log, args, state) {
  // strcpy()  arg1 is the Source. arg0 is the Destination.
  console.log('\n[+] _platform_strcpy()');
  var src_ptr  = args[1].toString()
  var src_string = Memory.readCString(args[1]);
  var src_byte_array = Memory.readByteArray(args[1],4);
  var textDecoder = new TextDecoder("utf-8");
  var decoded = textDecoder.decode(src_byte_array);
  console.log('[+] src_ptr\t-> ' , src_ptr);
  console.log('[+] src_string\t-> ' + src_string);
  console.log('[+] src_byte_array\t-> ' + src_byte_array);
  console.log('[+] src_byte_array size\t-> ' + src_byte_array.byteLength);
  console.log('[+] src_byte_array decoded\t-> ' + decoded);
},
```

The results:

```javascript
[+] _platform_strcpy()
[+] src_ptr	->  0x7ffeefbffaa6
[+] src_string	-> aaaa
[+] src_byte_array	-> [object ArrayBuffer]
[+] src_byte_array size	-> 4
[+] decoded	-> aaaa

[+] _platform_strcpy()
[+] src_ptr	->  0x7ffeefbffaab
[+] src_string	-> bbbb
[+] src_byte_array	-> [object ArrayBuffer]
[+] src_byte_array size	-> 4
[+] decoded	-> bbbb
```

#### Frida Objective-C Observer

```javascript
frida-ps -Uai  // get your bundle ID

frida --codeshare mrmacete/objc-method-observer -U -f funky-chicken.push-demo

[+] At the Frida prompt...
// Method isJailbroken
observeSomething('*[* isJail*]')

// Observe String compares
observeSomething('*[* isEqualToString*]');    

// A Class ( ObjC ) or Module (Symbol ). The first asterix indicates it can be eith Instance or Class method
observeSomething('*[ABC* *]');                                

// Watch Cookies
observeSomething('-[WKWebsiteDataStore httpCookieStore]');
observeSomething('-[WKWebAllowDenyPolicyListener *]');

// dump the URL to hit
observeSomething('-[WKWebView loadRequest:]');                

// you get all HTML, js, css, etc
observeSomething('-[WKWebView load*]');        

// Read the entire request
observeSomething('-[WKWebView loadHTMLString:baseURL:]') 

// Check for a custom UserAgent
observeSomething('-[WKWebView *Agent]');     
               
```

## Bypass anti-Frida checks

#### Rename Frida process

`bash -c "exec -a YDFooBar ./frida-server &"`

#### Set Frida-Server on host to a specific interface and port

`frida-server -l 0.0.0.0:19999 &`

#### Call Frida-server from Host

`frida-ps -ai -H 192.168.0.38:19999`

#### Trace on custom port

`frida-trace -m "*[NSURLSession* *didReceiveChallenge*]" -H 192.168.0.38:19999  -f com.youdog.rusty.tinyDormant`



## Cookies

#### Find Persisted Cookies

```bash
/private/var/mobile/Containers/Data/Application/<app guid, given at install time>/Library/Cookies/Cookies.binarycookies
```

#### Extract

```bash
scp -P 2222 root@localhost:/private/var/mobile/Containers/Data/Application/<App GUID>/Library/Cookies/Cookies.binarycookies cookies.bin

BinaryCookieReader: Written By Satishb3 (http://www.securitylearn.net
python BinaryCookieReader.py Cookie.Binarycookies-FilePath

Cookie : s_fid=0BBD745EA9BCF67F-366EC6EDEFA2A0E6; domain=.apple.com; path=/; expires=Thu, 14 Dec 2023;
Cookie : s_pathLength=homepage%3D2%2C; domain=.apple.com; path=/; expires=Fri, 14 Dec 2018;
Cookie : s_vi=[CS]v1|2E09D702852E4ACE-60002D37A0008393[CE]; domain=.apple.com; path=/; expires=Sun, 13 Dec 2020;
............
............
```

#### Find Cookies in Memory with Frida ( on real device & iOS Simulator )

```bash
$) ps -ax | grep -i WebKit.Networking
29163 ??         <longPath>/.../com.apple.WebKit.Networking

$) frida --codeshare mrmacete/objc-method-observer -p 29163

[PID::29163]-> %resume                           
[PID::29163]-> observeSomething('*[* cookiesWithResponseHeaderFields:forURL:]');
 ```

Results:
```javascript
+[NSHTTPCookie cookiesWithResponseHeaderFields:forURL:]
 cookiesWithResponseHeaderFields: {
     "Set-Cookie" = "EuConsent=<removed for brevity>; path=/; expires=Sat, 16 Nov 2019 14:51:01 GMT;";
 } (__NSSingleEntryDictionaryI)
 forURL: https://uk.yahoo.com/?p=us&guccounter=1 (NSURL)

 RET: (
     "<NSHTTPCookie
 	version:0
 	name:EuConsent
 	value:<removed for brevity>
 	expiresDate:'2019-11-16 14:51:01 +0000'
 	created:'2019-11-15 14:51:01 +0000'
 	sessionOnly:FALSE
 	domain:yahoo.com
 	partition:none
 	sameSite:none
 	path:/
 	isSecure:FALSE
  path:"/" isSecure:FALSE>"
 )
```

## Change iOS Version

_WARNING_: only change the minimum iOS version of a specific app's plist and not for the entire device. Things start to break - like calls into C libraries - when you change the device's read-only iOS version.

```bash
ssh onto device
root# cd /System/Library/CoreServices/
root# cat SystemVersion.plist
root# nano SystemVersion.plist
EDIT THE VALUE.  KEEP THE OLD VALUE!
```

## LLVM Instrumentation

```bash
https://developer.apple.com/library/archive/qa/qa1964/_index.html
otool -l -arch all my_framework | grep __llvm_prf  
nm -m -arch all my_app | grep gcov
```
