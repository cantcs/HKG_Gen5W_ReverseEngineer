# Reverse Engineering Hyundai/Kia/Genesis Android-based Gen5W Head-Units

Hyundai/Kia/Genesis cars have a few different types (generations) for their Head-Units (infotainment systems).  
Most of the wide-screen Head Units since 2019 are from GEN5W which can be either based on Android or based on Linux (ccOS) - both get periodic firmware updates that can be updated using a USB drive. This page is about reverse engineering the GEN5W Android Head-Units, patching their official firmwares to get adb, root, modify stock apks, and install third-party apks.

## Some history, credits, and references.

A few months ago when I got my new car I decided to hack into the Head-Unit (HU) to add some apps and customize some stuff - and this sent me back (after so many years) into the fantastic world of reverse-engineering and Android hacking. 

The first page I found about hacking Hyundai HUs was an old XDA thread with some discussions about how to enter engineering mode, how to enable adb, how third-party APKs were blocked, etc - but most of those findings were for old generations or for very old firmware versions and weren't working anymore. The real useful information was mostly found in Telegram/Discord groups:
- [Ioniq Dev Telegram Group](https://t.me/+GeTwB_AD7utjNmVk) is very active and has tons of information. Unfortunately this group is for **Gen5 Linux (not Android)**, but yet many ideas and tricks work similar for Gen5/Gen5W-Linux/Gen5W-Android. Some members of this group published some [interesting findings](https://gitlab.com/g4933/wideopen/-/tree/main), like the fact that firmware updates are encrypted using AES secret key, files are hashed, hashes are signed using RSA public-key cryptography, and they also found some methods to bypass the RSA checks.  
  Around early 2022 they found a way to do [ELF patching](https://gitlab.com/g4933/gen5w/navi_extended/-/blob/main/appnavi_payload_injector_patch/full_patcher_commented.sh) to inject [assembly code](https://gitlab.com/g4933/gen5w/navi_extended/-/blob/main/appnavi_payload_injector_patch/payload.s) into the navigation-app libraries, and this assembly-hook could run arbitrary commands (reading scripts from USB drive).  
- [KIA/Hyundai Android Modd](https://t.me/+1E4AJutHbvhkZjU1) is focused on Gen5-Android. Someone in that group had old firmware (where adb could still be enabled from engineering menu, and engineering menu password was historically leaked), and [Helloyunho](https://github.com/Helloyunho) asked this person to share some files like `uagentd`, `/etc/image.dat` (secret key), etc. By reverse engineering (and logs) she discovered that the navigation app did NOT had a RSA-signature validation, which means it was a good candidate for being tampered.
- [Helloyunho created an exploit for Gen5W-Androids](https://github.com/Helloyunho/gen5w-utils) based on the same idea (patching ELF Navi-libraries with C-code to run arbitrary scripts), and created a great [Gen5W Android Discord Group](https://discord.gg/KpwrAeHmQJ).  
Most things described in this page are things I learned in this Discord Group enriched with a few contributions on my own.  
Special thanks to Helloyunho, superdavex, UnjustifiedDev, and so many others who contributed to the group.


If you are looking for information on D-Audio2 generation check [greenluigi](https://programmingwithstyle.com/posts/howihackedmycar/) the series of posts [How I Hacked My Car](https://programmingwithstyle.com/posts/howihackedmycar/) (source code [here](https://github.com/greenluigi1/HyundaiFirmwareDecrypter)).  For D-Audio (v1) check [xakcop](https://xakcop.com/post/hyundai-hack/). Both were still based on password-protected ZIP file. For Gen5 (not Gen5W) check [Radoslav Gerganov](https://github.com/rgerganov/gen5fw).



## Limitations

There are some important limitations on what can currently be done:
- Gen5W is based on Android 4.4.2 (with some modifications) but Hyundai Mobis didn't made the full source code available (by the license agreement I think they should?).
- Without the right audio/video drivers it's impossible to rebuild a new working kernel, add new hardware modules, or upgrade to more recent Android versions.
- Google Play Services (part of `services.jar`) is blocked, and we can't just unblock it because they doesn't support Android 4.x anymore.  
  This means: no YouTube, no Google Play Store, no Gmail, Google Maps cannot load your profile/favorites.
- Some models do not have Wifi Module (but apps can use the modem internet if available).  
  I haven't yet found a way to install external wi-fi adapters, but I heard it's possible. 

If you want a full modern Android (to watch YouTube or any other recent apps), I suggest that you should buy an AI box like [CarlinKit](https://carlinkitcarplay.com/collections/carplay-ai-box), or [any other](https://www.amazon.com/s?k=car+ai+box).

## Requirements

In order to apply the methods described here you'll need:
- A Linux machine (can be a VM)
- One 64gb USB drive (maybe two if you have a recent firmware)
- Laptop (Windows is recommended) with Android USB Drivers and Tools (adb/fastboot).
- Male-to-male USB cable (to connect Laptop to Head Unit)

## How Firmware Updates Works

Firmware updates are basically TAR archives that can be downloaded and saved in a USB drive.

These tar archives contain some "core" files that are directly flashed as Android partitions:
- `boot` partition (contains Android kernel/OS/drivers), `system` partition (filesystem/apps), `recovery` partition (code to install new firmware updates from USB drive), `lk` (bootloader / little kernel), modem firmware, micom, etc.
- **Those partitions are all encrypted using AES-128-CBC**.
- Example: `/enc_system/enc_boot.img` is decrypted into `boot.img` that is flashed into `/boot` partition
- The secret key is **NOT** the same for all car models
- This key can be found in `/system/etc/image.dat` (it's the first 32 chars), after you get access to your HU

These tar archives also contain navigation app and maps stored in other tar files (`navi_backup.tar*` and `sw_backup.tar`):
- These files are basically just extracted on top of `/navi` partition (it's a partition only for navigation software)
- Some files in the tar are just unencrypted
- Executable files (or libs) are encrypted using AES-128-CBC
- The secret key is the SAME for EVERY Hyundai/Kia/Genesis car model (spoiler: it was [leaked](https://github.com/Helloyunho/gen5w-utils/blob/main/decrypt_navi.py))

On top of AES encryption there's also RSA-signatures:
- All files are hashed using SHA-224
- A digest of all hashes is encrypted using a lame XOR cryptography
- This digest is signed using RSA (only Hyundai has the private key, so we can't fake that signature)
- Updater programs will check if the RSA signature is authentic (using the corresponding public key, baked into the filesystem)
- Updater programs also checks (well, mostly) if the hashes in the signed digest are still matching the hashes of the actual files

The update process starts in the UI - we enter Settings menu and click Update button:
- Settings app communicates with `uagentd` (Update Agent Daemon), which will check USB drive, check RSA signature (both check if it's authentic and also check if the current hashes match what was signed)
- If everything looks good it will reboot into `recovery` mode.

The second part of the update process happens in recovery mode (`/sbin/recovery` from `recovery` partition):
- It will check RSA signature again (both check if it's authentic and also check if the current hashes match what was signed)
- It will decrypt the partitions and flash them one by one
- It will extract navigation tars (including `sw_backup.tar`) and decrypt the encrypted parts


## Main Exploit: How it Works

The major security flaw was discovered by [Helloyunho](https://github.com/Helloyunho/gen5w-utils) by disassembling `uagentd`/`recovery` and analyzing recovery logs:
- `uagentd` was NOT checking the `sw_backup.tar` hash, so that file can be tampered and doesn't need to match the hash that RSA-signed (currently this was fixed but there's still a hack to bypass that)
- `recovery` does NOT check `sw_backup.tar` hash either (still doesn't!)
- Encrypted files in `sw_backup.tar` are decrypted with a secret key that could be retrieved from the binaries - and now it has been [leaked](https://github.com/Helloyunho/gen5w-utils/blob/main/decrypt_navi.py)

Then being able to decrypt/encrypt navigator libraries she created the main exploit, based on method hooking:
- There is a [hook](https://github.com/Helloyunho/gen5w-utils/blob/main/hook.c) method that will look for a [shell script](https://github.com/Helloyunho/gen5w-utils/blob/main/run.sh) in your USB drive and will [invoke](https://github.com/Helloyunho/gen5w-utils/blob/main/hook.c#L255) it - allows you to run arbitrary code in the Android HU
- There is a Python code that can [patch](https://github.com/Helloyunho/gen5w-utils/blob/main/patch_navi.py) any ELF-method with the new code. So basically when the original method is called the hook will run instead
- The [main Python script](https://github.com/Helloyunho/gen5w-utils/blob/main/make_patched_firmware.py) will [look for a logging library](https://github.com/Helloyunho/gen5w-utils/blob/main/make_patched_firmware.py#L92), decrypt it, patch existing methods with the hook, and reencrypt it.  
  Then it will rebuild the non-signed hash list with new `sw_backup.tar` hash (so the XOR'ed hashes-digest is recreated, but there's no need to recreate the respective RSA signature, since that specific hash isn't compared)

By being able to run arbitrary code we extract any files from the Head-Unit (including the other AES keys used to encrypt/decrypt all firmare files other than the navigation), we can enable adb (and get a shell), or enter bootloader (and flash anything), etc.

## Patching Stock Firmware with the Exploit

After downloading an official firmware (or using an old downloaded copy, even better) you can patch it with the exploit. The steps below should all be done under Linux (steps below were tested in Ubuntu 22.04).

1. Install Python, PIP and other dependencies:
    ```sh
    sudo apt update -y
    sudo apt upgrade -y
    sudo apt install make automake autoconf libtool unzip python3 python3-pip -y
    ```

1. Build libtar (the library AND the command-line utility):
    ```sh
    cd ~
    git clone https://github.com/Parrot-Developers/libtar.git
    
    # make the lib
    cd libtar
    aclocal
    autoconf
    ./configure
    make
    
    # make the binary utility (libtar cli)
    cd libtar
    make
    
    # add to path
    export PATH="$PATH:$HOME/libtar/libtar" # or (not persistent): PATH="$PATH:$HOME/libtar/libtar"
    ```

1. Download Android NDK r19:
    ```sh
    sudo mkdir /android/
    cd /android/
    sudo wget https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip
    sudo unzip android-ndk-r19c-linux-x86_64.zip
    export NDK_ROOT=/android/android-ndk-r19c
    ```

1. Clone [Helloyunho repository](https://github.com/Helloyunho/gen5w-utils) and install dependencies:
    ```sh
    cd ~
    git clone https://github.com/Helloyunho/gen5w-utils.git
    cd ~/gen5w-utils
    python3 -m pip install -r requirements.txt
    ```

1. Build `hook.c` into `hook.o`:
    ```sh
    ./build_hook.sh
    ```
    The output (`hook.o`) is a binary object that will be injected (using [LIEF](https://github.com/lief-project/LIEF)) into a navigation-app library

1. Download [tc-write-misc.c](tc-write-misc.c?raw=true) utility and build it:    
    ```sh
    HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    HOST_ARCH="$(uname -m | tr '[:upper:]' '[:lower:]')"
    HOST_TAG="$HOST_OS-$HOST_ARCH"
    "$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG/bin/armv7a-linux-androideabi19-clang" -mthumb -fPIC -shared -fomit-frame-pointer -nostdlib -nodefaultlibs tc-write-misc.c -o tc-write-misc
    ```

1. Copy the downloaded firmware into some folder where we'll apply the patch (e.g. `/2023_Palisade_USA/`).  
   PS: You should do all these steps in a Linux filesystem (**POSIX-compliant**), if you try to patch firmware directly under the USB drive created by Navigation Updater (which only accepts FAT/NTFTS) it probably WON'T work, and you might get a bad tarfile.  
   PS: The only large file that you'll need is `sw_backup.tar`, so if you're copying firmware files to Linux to run the patching scripts you only have to copy this specific file and the other smaller files. After the patching process you can copy all these files (they will have been modified) back to the original place where you have all firmware files (probably an USB drive).

1. Now patch sw_backup.tar:  
  `python3 make_patched_firmware.py /2023_Palisade_USA/`  
  This will extract `sw_backup.tar`, find the right libraries to be patched, decrypt them, patch them with the hook, reencrypt, and will recalculate `sw_backup.tar` hash. The original RSA signature is preserved (as explained earlier the hash for tampered `sw_backup.tar` is not compared with whatever hash was signed)

1. Copy the firmware (with the modified files) to your USB drive.  
   Also copy `tc-write-misc` that you built (you'll need it later)

## Flashing the Patched Firmware (if your car has firmware older than Oct 2023)

If your car has old firmware (older than Oct 2023) you can just flash the patched firmware using the regular steps (Settings, Update button, etc.) - the HU will reboot and the update will proceed.

## Flashing the Patched Firmware (if your car has recent firmware)

In recent firmware versions (October 2023) `uagentd` was fixed to check `sw_backup.tar` hash (it should match what was signed by RSA private key). So basically a patched `sw_backup.tar` is NOT accepted anymore as valid. 

However `recovery` (which is where the real update occurs) still has a flaw, so there's a trick using two USB drives:
- In the first USB drive you copy the official firmware update (where `sw_backup.tar` matches the RSA-signed hashlist)
- In the the second one you put the patched firmware (with the recalculated hash for `sw_backup.tar`).  
  No need to create a new RSA signature (we wouldn't be able to do it anyway)
- In the Android UI we start the update process using the official firmware
- `uagent` will validate the RSA signature, check if the digest that was signed (a list of hashes) matches the real files (after they decrypted), and will reboot into recovery mode.
- When the HU reboots you should quickly swap USB drives
- During recovery mode `/sbin/recovery` will again validate RSA signature (check if it's authentic), decrypt files and check if the hashes in the signed digest matches the hashes from the real files. However `sw_backup.tar` is extracted under a different logic that still doesn't check if the signed-hash still matches the file hash. So update works and we can get our patched libraries.

## After you updated with Patched Firmware

Now that you have a patched firmware, every time you run navigation app the hooked-library will check if there is a script `run.sh` in the USB drive, and if the file exists then script will be executed.  

When the script is executed the hook saves a lock file in the USB drive, so if you need to run the script again you have to delete the lock file `XXlock` and launch navi again  
PS: in my experience sometimes you have to reboot the HU in order to stop navi process.

## Using Exploit for the First time

**\*\*IMPORTANT\*\*** - You'll need a Laptop (most people use Windows for this) and a male-to-male USB cable (to connect Laptop to Head Unit) - if you do not have that then do not proceed further (or at least do not enable adb).

The script [`run.sh`](https://github.com/Helloyunho/gen5w-utils/blob/main/run.sh) was automatically copied as part of `make_patched_firmware.py`, so probably that file is already in your USB drive.

Edit `run.sh` in your USB drive and replace it with the following:

   ```sh
  #!/system/bin/sh

  # Redirecting output to append to the file
  LOG_FILE="/storage/usb0/bash_log.txt"
  exec 1>"$LOG_FILE" 2>&1

  # COMMANDS
  echo "Copying recovery resources..." # this zip contains AES key and iv
  /system/bin/cp /system/etc/recovery-resource.dat /storage/usb0/recovery-resource.zip
  
  echo "Copying key/iv individually (if they exist)..."
  /system/bin/cp /system/etc/image*.dat /storage/usb0/
  /system/bin/cp /system/etc/iv*.dat /storage/usb0/

  echo "Pushing some utilities to the HU..." # copying to any writeable folder
  /system/bin/cp /storage/usb0/tc-write-misc /storage/navi/bin
  /system/bin/chmod 777 /storage/navi/bin/tc-write-misc 

  echo "backing-up boot.img..."
  /system/bin/dd if=/dev/block/platform/bdm/by-name/boot of=/storage/usb0/boot-backup.img
   ```

Plug that USB into your HU, and launch the navigator app (which may or may not start - don't worry, we can fix it later).  

Remove your USB drive and check if some files were copied there, as well as logs, and a lock file `XXlock`.

If everything worked fine, save those files (you'll need them later), and we can proceed with more tricks...

PS: Those files copied from HU to USB (`/system/etc/image.dat`, `/system/etc/iv.dat` if exists and `/system/etc/recovery-resource.dat`) are the AES key that can be used to decrypt all other firmware parts (other than navigation)

## Enabling ADB

Delete `XXlock`, edit `run.sh` and replace with the following commands:

   ```sh
  #!/system/bin/sh

  LOG_FILE="/storage/usb0/bash_log.txt"
  exec 1>"$LOG_FILE" 2>&1

  # COMMANDS
  echo "Enabling adb..."
  service call com.hkmc.misc 6 i32 5 # enables adb mode (usb drives wont work, android auto wont work)
  service call com.hkmc.misc 4 i32 4 # restart adb
  
  # as soon as we enable adb the USB drive will disconnect, 
  # so most likely log file will be empty this time
   ```

Launch navigator again. Remove USB drive and check for logs (no worry if it's empty) and for a new lockfile `XXLock`.  
If they are not there it means the hook didn't run - in this case reset the HU and try again (sometimes navi/lock freezes so you need to reboot)

If everything worked fine, you should be able to plug your Laptop and run `adb devices` and see the HU

## ADB

Now that you have `adb` enabled, you can connect from your laptop to the Head Unit.

I suggest Windows, but probably it should work with Linux/MacOS too.

For Windows you can get latest [Android Drivers here](https://developer.android.com/studio/run/win-usb) (latest_usb_driver_windows.zip).  
(I think that also contains tools you'll need like `adb.exe` and `fastboot.exe`)

Type `adb devices` to see if the connection is working.  
If it's not working probably you have bad drivers or a bad USB cable.

By typing `adb shell` you'll get a shell, but it's very limited since you don't have root yet (and important folders are all read-only).  

At this point (even without root) you can already upload some APKs (as long as they work with Android 4.4.2) to any writable folder - see later in this page.

PS: for now you should leave ADB enabled, BUT if you wanted to immediately disable it you could get an adb connection (`adb shell`) and run `service call com.hkmc.misc 6 i32 6` (sets back to host mode). (I think restarting adb with `service call com.hkmc.misc 4 i32 4` is probably not required).

## Important: Host Mode vs Acessory Mode

By enabling ADB the HU goes from **HOST MODE** to **ACCESSORY MODE**.

Accessory Mode means your Android HU is an accessory to something else (in case your Laptop running the adb client), so the following things will NOT work since they only work in HOST MODE:
- Your Android HU will not charge a connected phone (no power provided) 
- Your Android HU will not recognize a connected phone for Android Auto
- Your Android HU will not recognize USB drive (this means you can't even use Settings - Update Firmware)
- The navi exploit won't be able to find script in USB drive

This means that once you enter ADB mode (or BOOTLOADER mode explained later) you can only exit those modes (reverting back to HOST MODE) by using a Laptop with the right adb/fastboot drivers and a cable.

## Do I need root?

With the patched-navi exploit and the script in USB drive you'll be able to enable ADB mode, and then when using ADB you can disable ADB and get back to normal life (e.g. get Android Auto back). But there are not many things you can do without root, so you'll eventually need root for fun and helpful things:
- Unhide adb menu (so you can enable/disable from UI, no need to use a Laptop/cable and rely on the not-so-friendly exploit)
- Modify any APK (like adding new icons to the launcher)

There are two ways to get root:
- You can get TEMPORARY root by flashing a ClockworkMod Recovery (CWM) that is built for your chipset  
  (Currently only available for TCC897X chipsets)
- You can get PERMANENT root by flashing a modified `boot.img`

In both cases you will need the stock `boot.img`.

## Dumping boot.img from Android HU

Earlier in the initial script I told you to run this command:
```sh
/system/bin/dd if=/dev/block/platform/bdm/by-name/boot of=/storage/usb0/boot-backup.img
```
If this worked you should have now a dump of your current boot.img in your USB drive.

## Decrypt boot.img

Another way of getting boot.img is decrypting it from the official firmware. (and it should be exactly the same version that you have in your HU, so it's equivalent to the backup method).

First you need to get the AES secret key (and IV) for your car:
- The initial script also copied to your USB drive a file named `image.dat`.
- The first 32 chars of that file is the AES secret key
- The Initialization Vector (IV) is 16 bytes from 00 to 0F: `000102030405060708090A0B0C0D0E0F`
- In some rare cases you should have a different IV (if that's the case you should have `iv.dat` copied to your USB drive)
- If you can't find `image.dat` in USB drive then use `recovery-resource.zip` and extract it, it should have the same file(s) inside it.

Now you can extract the main firmware (e.g. `system_package_HMC.xxx.xxxx.Vxxx.xxx.xxxxxx.xxxxxx.tar`), and you should get a folder `enc_system` which contains encrypted images for all partitions (`enc_boot.img`, `enc_system.ext4`, `enc_recovery.img`, `enc_lk.rom`, etc). 

In order to decrypt `enc_boot.img` (or any other img) you should run this:

```sh
# Get the first 32 characters of image.dat - that's the AES key for your model
AESKEY="32-char-hex-string" 

# Initialization vector is the same for all firmware versions/geos (unless you have a file named iv.dat)
IV="000102030405060708090A0B0C0D0E0F"

# Decrypt files like this:
openssl aes-128-cbc -K $AESKEY -iv $IV -d -in ./enc_system/enc_boot.img -out ./system/boot.img
# or...
#openssl aes-128-cbc -K $AESKEY -iv $IV -d -in ./enc_system/enc_system.ext4 -out ./system/system.ext4
#... etc
```

AES does not have any way to validate if the secret was correct (sometimes wrong keys will crash but sometimes it will just decrypt into bad results), so you should validate the results:
- Open `boot.img` in a text editor
- Check if it starts with "ANDROID" (this means the key was correct)
- Check if right in the first line you can read `androidboot.selinux=disabled` among other readable strings.  
  (This means that IV is also correct. AES-CBC will [correctly decrypt the first block](https://security.stackexchange.com/questions/207633/decrypting-aes-128-cbc-leads-to-first-block-being-correct-the-rest-corrupt) even with the wrong IV).


## Decrypt system.ext4, recovery.img, etc.

Same as previous


## Patch boot.img to get Permanent Root

Now that you have the stock `boot.img` we can patch it to get permanent root.
If you just want TEMPORARY ROOT (using Clockwork Mod) just skip this step.

Patching `boot.img` means unpacking it, modifying it, and repacking it.

```sh
# Download Android Image Kitchen:
cd ~
git clone https://github.com/ndrancs/AIK-Linux-x32-x64
cd ~/AIK-Linux-x32-x64
chmod +x *.sh

# Unpack boot.img - the kernel will be unpacked into ./zImage, and the temp filesystem unpacked into ./ramdisk :
sudo ./unpackimg.sh ./system/boot.img # unpackimg should be executed

# Now edit (in any Linux editor!!!) ramdisk/default.prop, make the following changes:
# change ro.adb.secure from 1 to 0
# change ro.secure     from 1 to 0

# Now replace ./ramdisk/sbin/adbd with the adbd attached
# This patched adb daemon gives root privilege and allows "adb remount" command
# ("adb remount" enables you to "adb push" into a read-only folder after you remount it with "mount -o rw, remount /")

# Now repack ramdrive+kernel - they will be packed into a new file ./image-new.img :
sudo ./repackimg.sh

# rename
mv image-new.img boot-patched.img
```

Now you have `boot-patched.img`


## Enabling Bootloader Mode (Fastboot mode)

Now that we have adb working we can go ahead and get root, by flashing an unprotected bootloader (either the patched stock boot, or ClockworkMod)

**\*\*WARNING\*\*** - This is a tricky step because sometimes it's difficult to get a fastboot connection.  
Don't panic if you can't easily get a fastboot connection (usually it's just lack of drivers).  
Beware that there's a risk that you can't get a fastboot connection and therefore your device will be bricked.  
Do it on your own risk - I'm not responsible for any problems.

- **DO NOT PROCEED if** you did NOT upload `tc-write-misc` to HU  
  (you might have difficult to quit bootloader mode)
- **DO NOT PROCEED if** you don't have Laptop, usb cable, adb/fastboot drivers, or if you couldn't get an adb connection

This is how you can enter bootloader mode:

```sh
Open an `adb shell` and run this:
```sh
# let's schedule that subsequent boots should be in bootloader (fastboot mode)
/storage/navi/bin/tc-write-misc boot-bootloader
# reboot
/system/bin/reboot
```

This will write `boot-bootloader` into Android `misc` partition- (which means that next boot (and all subsequent boots until we change that) will start in "bootloader mode", and then it reboots the HU. After rebooting you'll see the splash screen (logo) stuck forever (Android won't load), that's normal - that's bootloader mode (aka fastboot mode).

Run `fastboot devices` to see if the connection is working. If you can't see the connection probably it means you have wrong drivers (in Windows open Device Manager, find the USB device, and if you see a yellow exclamation mark it means that the device wasn't recognized - try "Update driver" and point to the folder where you have Android USB INF drivers - if you see multiple options search for FASTBOOT or USB).

PS: this same result could be accomplished with `adb reboot bootloader`, but I prefer using `tc-write-misc` because in some stages you will need `tc-write-misc` (from inside Android OS), so it's important to check if it's working fine.

## Flashing boot-patched.img

Now after reboot you're in bootloader mode (fastboot mode). 

**DON'T FORGET THAT FLASHING A BAD BOOTLOADER (or bad adbd) CAN BRICK YOUR DEVICE** - do it at your own risk, ensure you know what you're doing

Copy boot-patched.img to your laptop and flash it to boot partition:

```fastboot flash boot boot-patched.img```

Boot ONCE into the full Android to see if it works (but don't clear yet the bootloader flag, so if anything goes wrong you can hopefully flash back to your previous boot.img):

```fastboot continue```

**If Android loads fine**, set the device to reboot subsequent boots into full Android:
```sh
# let's QUIT bootloader (schedule that subsequent boots should be back in regular Android OS)
/storage/navi/bin/tc-write-misc boot-normal
# reboot
/system/bin/reboot
```
PS: `adb reboot` would achieve same results but doesn't work in our patched adbd

PS: If anything goes wrong you can just reset the HU and you'll still be in bootloader mode - in which case you can just flash the previous boot.img (`fastboot flash boot boot-backup.img`)

## Writing to the read-only filesystem

Now that we have root open `adb shell` and run this:

```sh
# Make filesystem writeable (this is not permanent, clears every boot):
mount -o rw, remount /

# this file is what makes adb hidden from engineering mode
rm -f /system/etc/permissions/com.hkmc.software.engineermode.adb_hide.xml
```

After deleting `com.hkmc.software.engineermode.adb_hide.xml` now when you go to **engineering mode** you can go to modules menu, navigate to the 3rd page, and click 5 times in the bottom-right corner - then you'll see the adb tab appears on your left - so now you can enable and disable adb directly from UI.

The command `mount -o rw, remount /` should be executed inside Android and will remount the whole filesystem as writeable. After that command you can also push files to protected folders using `adb push` - but you have to first call `adb remount`.

## Alternative (only for TCC897X chipset): ClockWorkMod to get Temporary Root

If your chipset is TCC897X and you don't need permanent root you don't need to create and flash a boot-patched.img - you can instead just use a temporary [ClockWorkMod image](cwm_tcc897x.img?raw=true). It's similar to the other process, minor differences:
- You will still need to get stock boot (either through dump backup or through decryption)
- Enter bootloader mode (`adb reboot bootloader` should work, since this is stock abd)
- Instead of `boot-patched.img` you will flash ClockworkMod recovery (built for TCC897X chipset) as temporary boot:
 `fastboot flash boot cwm_tcc897x.img`
- `fastboot continue` to run ClockworkMod
- Get an `adb shell` (CWM has root privileges)
- File system is not mounted, so you need to manually mount it:
   ```sh
  mkdir /system;
  mount -t auto /dev/block/platform/bdm/by-name/system /system
   ```
- Do whatever you want (like deleting `adb_hide.xml`)
- Go back to bootloader (fastboot mode): `adb reboot bootloader`
- Flash again the regular stock boot.img: `fastboot flash boot boot-backup.img`  
  Img can be from a backup or from decrypting official firmware
- Reboot **once** into regular Android (to make sure the boot is fine): `fastboot continue`
- If it's all good, clear bootloader flag (so next boots are not fastboot): `adb reboot`
Please note that some of the adb options used above (`adb reboot bootloader` to enter bootloader mode, and `adb reboot` to exit and go back to normal mode) would NOT work in the Hyundai firmware (they removed many adbd options for security, that's why we use `tc-write-misc`), but it works in CWM.

To sum: with the CWM solution you can TEMPORARILY get root, and unhide adb, but after reverting back to stock boot you'll still have most of the folders as read-only (e.g. you can't easily modify an APK, you would have to flash CWM again).
So to avoid having to flash CWM again it might be helpful to run `chmod 777 -R /system/app` to be able to modify apks.


## Reverting the Patch from Navi Libraries

After you unhide ADB you won't need anymore the service calls (you can enable adb from menus) and you might not need anymore the navi/runsh exploit (because you have adb shell).

So if your navi was broken (or got slower) after the exploit you can revert the exploited libs, restoring them from the stock `sw_backup.tar`:

- Extract file `navi_backup\BIN\G45\enc_libExSLAndroidJNI.so` from `sw_backup.tar`
- Decrypt it (to `libExSLAndroidJNI.so`) using [decrypt_navi.py](https://github.com/Helloyunho/gen5w-utils/blob/main/decrypt_navi.py)
- Check owner/permissions of `/data/data/com.mnsoft.navi/BIN/libExSLAndroidJNI.so`
- `adb push` the unpatched file to that location
- Set back previous owner/permissions using `chown`/`chmod`.

<br/>
<hr/>
<br/>

# Congratulations!

Congratulations, you have rooted your Android Head-Unit!

There is not a ton things we can do, but...



## Installing Apps

Even without root (all you need is ADB) you can push APKs (as long as they work with Android 4.4.2) to any writable folder (with root you can push even to system folders).

Some nice Apps you can Install:
- [Google Maps 10.4.1](https://www.apkmirror.com/apk/google-inc/maps/maps-10-4-1-release/google-maps-navigate-explore-10-4-1-12-android-apk-download/#google_vignette)
- [Nova Launcher 5.5.4](https://www.apkmirror.com/apk/teslacoil-software/nova-launcher/nova-launcher-5-5-4-release/nova-launcher-5-5-4-android-apk-download/) (it unhides many hidden apps, and it can be used to launch all apps that are not available in stock launcher)

They can be pushed to `/system/priv-app` (even if you don't have root) using `adb push`:
```sh
adb push "E:\com.google.android.apps.maps_10.4.1-1004106030_minAPI19(arm64-v8a,armeabi-v7a,x86,x86_64)(nodpi)_apkmirror.com.apk" 
/system/priv-app/
```

The nice thing about `/system/priv-app` is that APKs there are automatically "available" as user-apps (Android scans that folder on each reboot), so they can be launched with `monkey`:
```sh
adb shell monkey -p com.google.android.apps.maps -c android.intent.category.LAUNCHER 1
```

Unfortunately stock launcher does NOT show all available apps (but later I'll update this document to explain how to add shortcuts to the stock launcher).

## Nova Launcher

After pushing Nova Launcher you may choose "which launcher to use" on each boot (obviously you can select any of the 2 options and click "use always"). I suggest sticking to the stock launcher (as I've mentioned it's possible to hack it and add a new shortcut to open Nova Launcher - I'll explain later). But even if you use Nova Launcher as your main Launcher I don't think you will get bricked or anything (as long as you can find there shortcuts to open stock launcher or engineering menu - I don't remember if they are available - so take care)

## Wi-Fi

My HU does not have wifi chip, but I think this is what you need to unblock your wifi:

Create `android.hardware.wifi.xml`:
```xml
<permissions>
    <feature name="android.hardware.wifi" />
</permissions>
```
Push it and enable wifi
```sh
adb push android.hardware.wifi.xml /system/etc/permissions/
settings put global wifi_on 1
```

Then you should see Wi-Fi in the UI settings. If you don't you can open Wi-Fi settings with  
`adb shell am start -n com.android.settings/.wifi.WifiStatusTest` or  
`adb shell am start -a android.net.wifi.PICK_WIFI_NETWORK`

(`am start` is used to launch apps by the activity name)

## Modem Settings

If you want to play with Modem settings:  
`adb shell am start --user 0 -n com.hkmc.system.app.modem.engineering/com.hkmc.system.app.modem.engineering.ModemEngineerModeActivity`

## Car CAN Bus/Micom

Haven't explored this yet, but looks fun:  
https://programmingwithstyle.com/posts/howihackedmycarpart4/

<!--
## Wireless Carplay

Some people tried enabling it by pushing a similar permissions xml:  
`adb push com.hkmc.software.connectivity.carplay_wireless.xml /system/etc/permissions/`
Looks like that wasn't enough

## Adding Nova Launcher (or other apps) to Stock Launcher (US Version)
(to do...)

## Adding Nova Launcher to Stock Launcher (KR Version)
(to do...)

## Disassembling boot.img
init files, `uagentd`, `/sbin/adbd`

## Disassembling recovery.img
`/sbin/recovery`

## Disassembling Little Kernel (LK.ROM)

## Protecting Against OTA Updates

## Protecting Against Dealer Updates
- Shortcut to eng mode
- adb enable/disable
-->


<br/>
<hr/>
<br/>

# Support

Reach out to [Gen5W Android Discord Group](https://discord.gg/KpwrAeHmQJ) or open a Github issue.

# Contributions

I'm trying to keep in the main page only the basics, if you have contributions to share please open an issue describing what you have accomplished. Relevant findings will eventually be linked here or added to the main document. Feel free to PR any fixes or improvements to this page.


## Legal

This repository is NOT sharing any copyrighted software, patents, secrets, or anything that couldn't be obtained by legal means, so it does not violate US laws or EU laws. Reverse engineering is expressly protected under copyright law, as long as you got the product through legal means.

I do NOT encourage or endorse any kind of illegal action.

I agree with greenluigi that [Hyundai platform should be more open](https://programmingwithstyle.com/posts/howihackedmycarpart5/).