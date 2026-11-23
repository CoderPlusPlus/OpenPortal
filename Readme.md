# OpenPortal

**Give your Meta Portal its Google apps back.**

Meta quietly walked away from the Portal, and a lot of what made the device useful went
with it. OpenPortal puts the missing pieces back: it sets up Google Play Services and the
Play Store, and it installs the **standard Facebook Messenger** app — the same build you'd
get from an app store, not a patched copy — so it updates like a normal app instead of
needing to be patched by hand.

## Disclaimer
USE AT YOUR OWN RISK.  I AM NOT RESPONSIBLE IF THE SCRIPT RESULTS IN A BRICKED DEVICE!

I've tested the script myself, but like any script that uses exploits, there's always a
small risk of a boot loop or other unrecoverable error happening.  You agree by using the
script that you have read and understand this warning.

## Device fingerprint
Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys

## How to Run

### Prerequisites

Before you start, gather these:

1. **A Windows PC** and a **USB cable that carries data** (not a charge-only cable).

2. **A first-generation Meta Portal (codenamed "aloha").** That's the **15.6-inch Portal+** or
   the **10-inch Portal** — the 2018 models, which share the same firmware. OpenPortal is
   built for that firmware only. (The underlying exploit also supports later Portals —
   Portal Go, Portal Mini, Portal TV, and the second-generation Portals — but OpenPortal's
   script is written for the first-generation "aloha" models, so those others aren't
   supported here, though they could probably be made to work fairly easily.)

3. **Wi-Fi on the Portal.** Connect the Portal to a Wi-Fi network before you start. The
   script uses a small wireless helper channel to recover the Portal if it restarts
   mid-way, and that channel needs the Portal to have a network address.

4. **Four Google app files.** The script can't fetch these for you, so download them by
   hand from APKMirror and put them in the **`stack`** folder next to this Readme (create
   the folder if it isn't already there):

   - **Google Play Services 26.44.32** —
     [download page](https://www.apkmirror.com/apk/google-inc/google-play-services/google-play-services-26-44-32-release/google-play-services-26-44-32-100400-1015688330-3-android-apk-download/) —
     make sure the variant is **arm64-v8a + armeabi-v7a · Android 9.0+ · nodpi**, and
     download the **APK** (not the "Bundle").
   - **Google Services Framework 9** —
     [download page](https://www.apkmirror.com/apk/google-inc/google-services-framework/google-services-framework-9-release/google-services-framework-9-3-android-apk-download/) —
     the variant is **noarch · Android 9.0+ · nodpi**.
   - **Google Account Manager 7.1.2** —
     [download page](https://www.apkmirror.com/apk/google-inc/google-account-manager/google-account-manager-7-1-2-release/google-account-manager-7-1-2-android-apk-download/) —
     the variant is **noarch · Android 6.0+ · nodpi**.
   - **Google Play Store 53.3.22** —
     [download page](https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-53-3-22-release/google-play-store-53-3-22-24-0-pr-986337757-5-android-apk-download/) —
     make sure the variant is **arm64-v8a + x86 + x86_64 · Android 7.0+ · nodpi**, and
     download the **Bundle** (the Play Store must go in as a bundle).

   If any of these are missing, the script will tell you exactly which one it needs.

The script fetches its own helper tools (adb, Java, Python, a small library for reading
app signatures, and simpleperf) automatically, and it can download Messenger by itself
too — so those four Google files are the only things you have to gather by hand.

### Steps

1. Plug the Portal into your PC with the USB cable.  The computer needs to stay plugged in
   and left running for the duration of the script.  The script may take 15-30 minutes to 
   complete.
2. On the Portal, open **Settings → Debug** and tap on **ADB Enabled**.  
3. Watch the Portal's screen — a **"Allow USB debugging?"** prompt will appear. Tap
   **Allow** (tick "always allow" if offered).
4. On your PC, open this folder and **double-click `OpenPortal.cmd`**.
5. For the most part, the script just does its thing.  Towards the end it will ask you if you 
   want to install Facebook Messenger.  This is because an app on the Portal uses the same-named
   permission as Messenger does and that breaks installing Messenger.  So we add Messenger's cert
   to that app's previous certs so that Messenger install is allowed.  You don't have to install
   Messenger, but I give the option since the fix gets applied regardless. The Portal will reboot 
   a few times in order to get the exploit to work, so its screen will go dark and come back. 
   That's expected behavior and is nothing to worry about.  It may reboot many times. Just watch 
   the script output for errors.
6. When you see the box that says **"Done!  Your Portal has been opened!"**, the script is finished
   and Play Store is installed and ready to use!
   
NOTE: While it runs, you'll see several reboots and may see things on the script like:

INSTALL_ATTEMPT_RESULT attempt=1 success=0 early_failure=0

That's ok.  The exploit it uses to grant Google Services the permissions it needs is based
on very specific timing and takes a few reboots to get the timing perfect.  If a real error
happens the log will use all red text and give detail on the error.  I know the output looks
overwhelming and may be scary to some, but it's very useful if something doesn't work.  You
can post your results to a github issue and I can see what happened.

### Your Opened Portal

Your portal now has the Google Play Store installed and holding the privileges it needs to 
function normally.  Open the Play Store, log in, and enjoy all of the apps that Meta took 
away.  I've personally tested Google Home, Photos, YouTube, YouTube Music, Spotify, and Netflix.

If you run into problems, please open an issue on GitHub and I'll do my best to help!

## Special Thanks and Licenses

I'd like to give a heartfelt thanks to all of the devs that contributed to the tools that Open Portal uses.  Without their hard work, getting Google Play working on the portal wouldn't be possible.  Thank you!

OpenPortal stands on the work of the projects below.  Each is listed with the credit it asks for and a link to its home.

**portal-root-kiosk-satellite** — the root exploit and provisioning tool that does the real work.  It includes a port of the public GhostLock exploit (CVE-2026-43499).

Licensed under the **Apache License 2.0** · © jxlarrea (Kiosk Satellite)
https://github.com/jxlarrea/portal-root-kiosk-satellite

*Modified for OpenPortal: `exploit/src/fops.c` and `tools/provision_portal.py` in this project were changed to add the permission-grant steps OpenPortal relies on.*

**KernelSnitch** — the timing side-channel technique the exploit uses to work its way around the kernel.

Licensed under the **MIT License** · © Lukas Maar
https://github.com/lukasmaar/kernelsnitch

**jhash (lookup3)** — the hash function used inside the exploit.

**Public domain** · © Bob Jenkins
https://burtleburtle.net/bob/hash/

**apkeep** — downloads the genuine Messenger app.

Licensed under the **MIT License** · © Electronic Frontier Foundation (EFF)
https://github.com/EFForg/apkeep

The tools below are downloaded from their official sources when they're needed, and aren't part of this package.  They're thanked here, but OpenPortal doesn't redistribute them.

**Android SDK Platform-Tools (adb)** — how OpenPortal talks to the Portal over USB.

Licensed under the **Apache License 2.0** · © Google
https://developer.android.com/tools/releases/platform-tools

**apksig** — reads an app's signing certificate, so OpenPortal can match Messenger's.

Licensed under the **Apache License 2.0** · © The Android Open Source Project
https://android.googlesource.com/platform/tools/apksig

**Eclipse Temurin (Java)** — runs the small helper that reads app signatures.

Licensed under the **GPLv2 with the Classpath Exception** · © Eclipse Adoptium
https://adoptium.net/

**Python** — runs the provisioning tool.

Licensed under the **Python Software Foundation License** · © Python Software Foundation
https://www.python.org/

**simpleperf** — finds the kernel's memory layout before the exploit runs.

Licensed under the **Apache License 2.0** · © The Android Open Source Project
https://android.googlesource.com/platform/prebuilts/simpleperf

The full text of every license listed above is in the **`THIRD-PARTY-NOTICES.md`** file next to this Readme.  OpenPortal's own code is released into the public domain under the **Unlicense** — see the **`LICENSE`** file.
